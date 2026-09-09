"""ml-classifier daemon for T-Pot.

Polls Elasticsearch ``logstash-*`` indices, classifies each new honeypot
event with the bundled multi-class model (or a rule-based fallback when
no model is loaded), and writes the result to ``ml-analysis-YYYY.MM.dd``.

Attack-vs-benign is decided by ``rule_label.is_attack(label)``: any label
other than ``Etc`` is treated as an attack. No separate binary model is
trained or loaded.

This container reads from T-Pot's existing ELK stack only — it does not
modify Logstash, Kibana, or any honeypot. Drop-in sidecar.

Environment:
    ES_HOST                Elasticsearch URL (default: http://elasticsearch:9200)
    ES_SOURCE_INDEX        Source index pattern (default: logstash-*)
    ES_TARGET_PREFIX       Target index prefix (default: ml-analysis-)
    POLL_INTERVAL_SEC      Seconds between polls (default: 60)
    BATCH_SIZE             Max docs per poll (default: 1000)
    MODEL_DIR              Directory holding *.pkl + encoders.json (default: /opt/ml-classifier/models)
    STATE_DIR              Directory for poll cursor (default: /data/ml-classifier)
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from elasticsearch import Elasticsearch, helpers

import feature_extract
import rule_label
import mitre

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
SOURCE_INDEX = os.getenv("ES_SOURCE_INDEX", "logstash-*")
TARGET_PREFIX = os.getenv("ES_TARGET_PREFIX", "ml-analysis-")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SEC", "60"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "1000"))
MODEL_DIR = Path(os.getenv("MODEL_DIR", "/opt/ml-classifier/models"))
STATE_DIR = Path(os.getenv("STATE_DIR", "/data/ml-classifier"))
MODEL_VERSION = os.getenv("MODEL_VERSION", "rule-1.0")
# If model confidence is below this threshold the prediction is treated as
# "Etc" (benign/unknown). Lowers false-positive rate on out-of-distribution
# traffic (e.g. legitimate connections that never appear in honeypot data).
CONF_THRESHOLD = float(os.getenv("CONF_THRESHOLD", "0.5"))

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ml-classifier")

_running = True


def _stop(signum, _frame):
    global _running
    log.info("signal %s received, draining…", signum)
    _running = False


signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)


def _load_models():
    multi = None
    encoders: dict = {}
    if (MODEL_DIR / "encoders.json").exists():
        with (MODEL_DIR / "encoders.json").open(encoding="utf-8") as f:
            encoders = json.load(f)
    if (MODEL_DIR / "multi_model.pkl").exists():
        multi = joblib.load(MODEL_DIR / "multi_model.pkl")
        log.info("multi model loaded")
    else:
        log.warning("no trained model found, falling back to rule-based labels")
    return multi, encoders


def _model_signature() -> tuple:
    """mtime tuple used to detect model file replacement at runtime."""
    sig = []
    for name in ("multi_model.pkl", "encoders.json"):
        p = MODEL_DIR / name
        sig.append(p.stat().st_mtime if p.exists() else 0.0)
    return tuple(sig)


CURSOR_PATH = STATE_DIR / "cursor.json"
BOOTSTRAP_WINDOW = os.getenv("BOOTSTRAP_WINDOW", "now-5m")


def _load_cursor() -> list | None:
    """Cursor is the ``sort`` array from the last processed hit.

    Stored as JSON so we can safely round-trip mixed types
    (epoch_millis int + _seq_no int).
    """
    if CURSOR_PATH.exists():
        try:
            return json.loads(CURSOR_PATH.read_text())
        except (ValueError, OSError):
            log.warning("malformed cursor file, ignoring")
    return None


def _save_cursor(values: list) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    CURSOR_PATH.write_text(json.dumps(values))


def _classify_doc(doc: dict, multi, encoders: dict) -> dict:
    feats = feature_extract.extract(doc, encoders)
    X = np.array([feats])

    label = rule_label.label_from_doc(doc)
    multi_conf = 100.0
    model_used = "rule"

    if multi is not None:
        try:
            proba = multi.predict_proba(X)[0]
            max_prob = float(max(proba))
            if max_prob >= CONF_THRESHOLD:
                label = str(multi.predict(X)[0])
                multi_conf = round(max_prob * 100, 1)
            else:
                # Low confidence → treat as benign/unknown rather than
                # forcing a wrong attack label. Likely out-of-distribution
                # traffic the model has never seen during training.
                label = "Normal"   # out-of-distribution → treat as benign
                multi_conf = round(max_prob * 100, 1)
            model_used = "ml"
        except Exception as e:  # noqa: BLE001
            log.warning("multi classify failed: %s", e)

    is_atk = rule_label.is_attack(label)
    score = mitre.score_for(label) if is_atk else 0
    return {
        "ml_label": label,
        "ml_is_attack": bool(is_atk),
        "ml_multi_conf": multi_conf,
        "mitre_score": score,
        "mitre_technique": mitre.technique_for(label),
        "model_used": model_used,
        "model_version": MODEL_VERSION,
    }


def _target_index_for(ts_iso: str) -> str:
    try:
        d = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        d = datetime.now(timezone.utc)
    return f"{TARGET_PREFIX}{d.strftime('%Y.%m.%d')}"


def _build_action(src_doc: dict, src_index: str, src_id: str, result: dict) -> dict:
    ts = src_doc.get("@timestamp") or datetime.now(timezone.utc).isoformat()
    return {
        "_op_type": "create",
        "_index": _target_index_for(ts),
        "_id": src_id,
        "_source": {
            "@timestamp": ts,
            "source_doc_id": src_id,
            "source_index": src_index,
            "src_ip": src_doc.get("src_ip"),
            "dest_ip": src_doc.get("dest_ip"),
            "dest_port": src_doc.get("dest_port"),
            "honeypot": src_doc.get("type"),
            **result,
        },
    }


def _poll_once(es: Elasticsearch, cursor: list | None, multi, encoders: dict) -> list | None:
    """Run one polling cycle.

    Uses search_after with a (@timestamp, _seq_no) compound key so that
    documents sharing the same millisecond timestamp don't get skipped or
    reprocessed forever.

    Returns the cursor for the next call (last hit's ``sort`` array), or the
    input cursor unchanged if no new docs were found.
    """
    body: dict = {
        "size": BATCH_SIZE,
        "sort": [
            {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
            {"_seq_no": {"order": "asc", "unmapped_type": "long"}},
        ],
    }
    if cursor:
        body["query"] = {"match_all": {}}
        body["search_after"] = cursor
    else:
        body["query"] = {"range": {"@timestamp": {"gte": BOOTSTRAP_WINDOW}}}

    resp = es.search(index=SOURCE_INDEX, body=body)
    hits = resp.get("hits", {}).get("hits", [])
    if not hits:
        return cursor

    actions = [
        _build_action(hit["_source"], hit["_index"], hit["_id"],
                      _classify_doc(hit["_source"], multi, encoders))
        for hit in hits
    ]
    ok, errors = helpers.bulk(es, actions, raise_on_error=False, raise_on_exception=False)
    log.info("polled=%d, indexed=%d, errors=%d", len(hits), ok, len(errors) if errors else 0)

    return hits[-1].get("sort", cursor)


def main() -> int:
    log.info("starting ml-classifier  source=%s  target=%s*  interval=%ss",
             SOURCE_INDEX, TARGET_PREFIX, POLL_INTERVAL)
    multi, encoders = _load_models()
    last_sig = _model_signature()
    es = Elasticsearch(ES_HOST, request_timeout=30)
    cursor = _load_cursor()
    log.info("resume cursor: %s", cursor or f"(none, bootstrap window={BOOTSTRAP_WINDOW})")

    while _running:
        # Hot-reload model if its file changed since last poll.
        sig = _model_signature()
        if sig != last_sig:
            log.info("model files changed on disk → reloading")
            try:
                multi, encoders = _load_models()
                last_sig = sig
            except Exception as e:  # noqa: BLE001
                log.warning("model reload failed, keeping previous models: %s", e)

        try:
            new_cursor = _poll_once(es, cursor, multi, encoders)
            if new_cursor and new_cursor != cursor:
                cursor = new_cursor
                _save_cursor(cursor)
        except Exception as e:  # noqa: BLE001
            log.exception("poll cycle failed: %s", e)
        for _ in range(POLL_INTERVAL):
            if not _running:
                break
            time.sleep(1)

    log.info("shut down cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
