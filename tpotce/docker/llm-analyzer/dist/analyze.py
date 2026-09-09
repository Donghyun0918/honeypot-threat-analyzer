"""llm-analyzer daemon for T-Pot.

Polls ``ml-analysis-*`` for high-risk events (``mitre_score >= MIN_SCORE``),
asks a Korean LLM for a second-stage assessment, and writes the result to
``llm-analysis-YYYY.MM.dd``.

Companion to ml-classifier: that sidecar decides *what* an event is, this one
explains *what it means and what to do about it*, in Korean. Reads ES and
writes its own index only — no honeypot, Logstash or Kibana state is touched.

Because an LLM call costs seconds (not microseconds like a LightGBM predict),
this daemon deliberately processes a small batch per cycle and is driven by
``mitre_score`` so only events worth the spend are analysed.

Environment:
    ES_HOST                Elasticsearch URL (default: http://elasticsearch:9200)
    ES_SOURCE_INDEX        Source index pattern (default: ml-analysis-*)
    ES_TARGET_PREFIX       Target index prefix (default: llm-analysis-)
    MIN_SCORE              Minimum mitre_score to analyse (default: 70)
    POLL_INTERVAL_SEC      Seconds between polls (default: 120)
    BATCH_SIZE             Max docs analysed per poll (default: 20)
    BOOTSTRAP_WINDOW       First-run lookback when no cursor exists (default: now-24h)
    STATE_DIR              Directory for the poll cursor (default: /data/llm-analyzer)
    LLM_PROVIDER           ollama | openai | anthropic | gemini (default: ollama)
    LLM_MODEL              Model name (provider-specific default)
    LLM_MAX_RETRIES        Retries per document before falling back (default: 2)
    LLM_SEVERITY           derive (default) | model — who judges severity
    WRITE_FALLBACK         Write a rule-based doc when the LLM fails (default: true)
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

from elasticsearch import Elasticsearch, helpers

import prompt_ko
import providers

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
SOURCE_INDEX = os.getenv("ES_SOURCE_INDEX", "ml-analysis-*")
TARGET_PREFIX = os.getenv("ES_TARGET_PREFIX", "llm-analysis-")
MIN_SCORE = float(os.getenv("MIN_SCORE", "70"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SEC", "120"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "20"))
BOOTSTRAP_WINDOW = os.getenv("BOOTSTRAP_WINDOW", "now-24h")
STATE_DIR = Path(os.getenv("STATE_DIR", "/data/llm-analyzer"))
MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "2"))
WRITE_FALLBACK = os.getenv("WRITE_FALLBACK", "true").lower() != "false"
# "derive" (default): severity/risk come from mitre_score and the model is
# asked only for prose. "model": the model judges, floored by the score.
# Measured on qwen2.5:3b, the model landed below the floor 10/10 times and
# few-shot examples did not change that — see prompt_ko.build_prompt.
ASK_SEVERITY = os.getenv("LLM_SEVERITY", "derive").strip().lower() == "model"

CURSOR_FILE = STATE_DIR / "cursor.json"
TEMPLATE_NAME = "llm-analysis"

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("llm-analyzer")

_running = True


def _stop(signum, _frame):
    global _running
    log.info("signal %s received, draining…", signum)
    _running = False


signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)


# ── index template ────────────────────────────────────────────────────────
# Consumers aggregate on `severity` as a plain keyword field and on
# `risk_score` as a number. Under ES dynamic mapping `severity` would become
# `text` (+ a `.keyword` subfield) and the terms aggregation would fail with
# "Fielddata is disabled", which both threat-console and the Spring backend
# swallow into an empty chart. Pinning the mapping up front avoids that.
INDEX_TEMPLATE = {
    "index_patterns": [f"{TARGET_PREFIX}*"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "severity": {"type": "keyword"},
                "risk_score": {"type": "float"},
                "mitre_score": {"type": "float"},
                "ttp_inferred": {"type": "keyword"},
                "ml_label": {"type": "keyword"},
                "src_ip": {"type": "ip"},
                "dest_port": {"type": "integer"},
                # `honeypot.keyword` is aggregated on, so keep the default
                # text+keyword shape rather than a bare keyword.
                "honeypot": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                },
                "summary_ko": {"type": "text"},
                "solution_ko": {"type": "text"},
                "llm_status": {"type": "keyword"},
                "severity_source": {"type": "keyword"},
                "llm_provider": {"type": "keyword"},
                "llm_model": {"type": "keyword"},
                "source_doc_id": {"type": "keyword"},
                "source_index": {"type": "keyword"},
            }
        },
    },
}


def _ensure_template(es: Elasticsearch) -> None:
    try:
        es.indices.put_index_template(name=TEMPLATE_NAME, body=INDEX_TEMPLATE)
        log.info("index template %r ensured for %s*", TEMPLATE_NAME, TARGET_PREFIX)
    except Exception as e:  # noqa: BLE001
        # Non-fatal: without the template aggregations degrade, but ingestion
        # still works and the operator sees this warning.
        log.warning("could not put index template (continuing): %s", e)


def _ensure_field_mappings(es: Elasticsearch) -> None:
    """Push the template's field types onto indices that already exist.

    An index template only applies at index *creation*. When a new field is
    added to the template (as `severity_source` was), documents written to an
    index created earlier get it under dynamic mapping — `keyword` becomes
    `text`, and every terms aggregation on it fails with "Fielddata is
    disabled", which the dashboard's consumers swallow into an empty chart.
    That is the same silent failure the template was introduced to prevent, so
    close it here too: adding a field to an existing mapping is allowed, and a
    field already mapped with a conflicting type is reported rather than
    hidden — that one needs a reindex.
    """
    props = INDEX_TEMPLATE["template"]["mappings"]["properties"]
    try:
        existing = es.indices.get(index=f"{TARGET_PREFIX}*", ignore_unavailable=True)
    except Exception as e:  # noqa: BLE001
        log.warning("could not list existing indices: %s", e)
        return

    for index in existing:
        try:
            es.indices.put_mapping(index=index, body={"properties": props})
        except Exception as e:  # noqa: BLE001
            log.warning(
                "%s has a field whose type conflicts with the template "
                "(aggregations on it will return empty; reindex to fix): %s",
                index, str(e)[:200],
            )


# ── cursor persistence ────────────────────────────────────────────────────
def _load_cursor() -> list | None:
    try:
        with CURSOR_FILE.open(encoding="utf-8") as f:
            return json.load(f).get("sort")
    except (OSError, ValueError):
        return None


def _save_cursor(values: list) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CURSOR_FILE.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump({"sort": values}, f)
        tmp.replace(CURSOR_FILE)
    except OSError as e:
        log.warning("could not persist cursor: %s", e)


# ── analysis ──────────────────────────────────────────────────────────────
def _analyse_doc(provider: providers.Provider, doc: dict) -> dict:
    """Run one document through the LLM, retrying transient failures.

    Always returns a result dict; on exhaustion it degrades to the rule-based
    fallback so a flaky provider cannot stall the cursor.
    """
    prompt = prompt_ko.build_prompt(doc, ask_severity=ASK_SEVERITY)
    last_err = "unknown"
    for attempt in range(1, MAX_RETRIES + 2):
        try:
            raw = provider.complete(prompt)
            result = prompt_ko.parse_response(raw, doc, ask_severity=ASK_SEVERITY)
            result["llm_status"] = "ok"
            return result
        except (providers.ProviderError, ValueError, KeyError) as e:
            last_err = str(e)[:300]
            log.warning("analysis attempt %d/%d failed: %s", attempt, MAX_RETRIES + 1, last_err)
            if attempt <= MAX_RETRIES:
                time.sleep(min(2 ** attempt, 10))

    result = prompt_ko.fallback_result(doc, last_err)
    result["llm_status"] = "fallback"
    return result


def _already_analysed(es: Elasticsearch, ids: list[str]) -> set[str]:
    """Return the subset of ``ids`` that already exist in the target indices.

    The `create` op-type already makes writes idempotent, but that check
    happens *after* the LLM call — so a lost cursor (wiped state volume,
    fresh container) would re-bill the whole bootstrap window before ES
    rejects the duplicates. Filtering up front keeps the spend idempotent
    too, which matters because the LLM is the expensive part of this daemon.
    """
    if not ids:
        return set()
    try:
        resp = es.search(
            index=f"{TARGET_PREFIX}*",
            body={"size": len(ids), "query": {"ids": {"values": ids}}, "_source": False},
            ignore_unavailable=True,
        )
        return {h["_id"] for h in resp.get("hits", {}).get("hits", [])}
    except Exception as e:  # noqa: BLE001
        # Degrade to the `create` guard rather than stalling the pipeline.
        log.warning("dedup pre-check failed, relying on create-conflicts: %s", e)
        return set()


def _target_index_for(ts_iso: str) -> str:
    try:
        d = datetime.fromisoformat(str(ts_iso).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        d = datetime.now(timezone.utc)
    return f"{TARGET_PREFIX}{d.strftime('%Y.%m.%d')}"


def _build_action(src_doc: dict, src_index: str, src_id: str,
                  result: dict, provider: providers.Provider) -> dict:
    ts = src_doc.get("@timestamp") or datetime.now(timezone.utc).isoformat()
    return {
        # `create` keyed on the source document id makes re-processing a
        # no-op: an event is never analysed (or billed) twice.
        "_op_type": "create",
        "_index": _target_index_for(ts),
        "_id": src_id,
        "_source": {
            "@timestamp": ts,
            "source_doc_id": src_id,
            "source_index": src_index,
            "src_ip": src_doc.get("src_ip"),
            "dest_port": src_doc.get("dest_port"),
            "honeypot": src_doc.get("honeypot"),
            "ml_label": src_doc.get("ml_label"),
            "mitre_score": src_doc.get("mitre_score"),
            "mitre_technique": src_doc.get("mitre_technique"),
            "llm_provider": provider.name,
            "llm_model": provider.model,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            **result,
        },
    }


def _poll_once(es: Elasticsearch, provider: providers.Provider, cursor: list | None) -> list | None:
    """Analyse one batch of high-risk events. Returns the next cursor."""
    filters: list = [{"range": {"mitre_score": {"gte": MIN_SCORE}}}]
    body: dict = {
        "size": BATCH_SIZE,
        "sort": [
            {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
            {"_seq_no": {"order": "asc", "unmapped_type": "long"}},
        ],
    }
    if cursor:
        body["search_after"] = cursor
    else:
        filters.append({"range": {"@timestamp": {"gte": BOOTSTRAP_WINDOW}}})
    body["query"] = {"bool": {"filter": filters}}

    resp = es.search(index=SOURCE_INDEX, body=body, ignore_unavailable=True)
    hits = resp.get("hits", {}).get("hits", [])
    if not hits:
        return cursor

    done = _already_analysed(es, [h["_id"] for h in hits])

    actions = []
    processed = 0   # hits consumed, including ones skipped before/after the LLM call
    skipped = 0
    analysed = 0
    for hit in hits:
        if not _running:
            log.info("stopping mid-batch; %d docs analysed this cycle", analysed)
            break
        if hit["_id"] in done:
            processed += 1
            continue
        result = _analyse_doc(provider, hit["_source"])
        processed += 1
        analysed += 1
        if result.get("llm_status") == "fallback" and not WRITE_FALLBACK:
            # Operator chose not to store rule-based stand-ins. The event is
            # dropped from LLM analysis; the cursor still advances so a
            # persistently failing provider cannot wedge the pipeline.
            skipped += 1
            continue
        actions.append(_build_action(hit["_source"], hit["_index"], hit["_id"], result, provider))

    if processed == 0:
        return cursor

    next_cursor = hits[processed - 1].get("sort", cursor)

    if not actions:
        log.info("polled=%d, cached=%d, analysed=%d, indexed=0, skipped_fallback=%d",
                 len(hits), len(done), analysed, skipped)
        return next_cursor

    ok, errors = helpers.bulk(es, actions, raise_on_error=False, raise_on_exception=False)
    # `create` conflicts mean "already analysed" — expected on overlap, not an error.
    conflicts = sum(
        1 for e in (errors or [])
        if isinstance(e, dict) and e.get("create", {}).get("status") == 409
    )
    real_errors = (len(errors) if errors else 0) - conflicts
    fallbacks = sum(1 for a in actions if a["_source"].get("llm_status") == "fallback")
    log.info(
        "polled=%d, cached=%d, analysed=%d, indexed=%d, conflicts=%d, errors=%d, fallback=%d, skipped=%d",
        len(hits), len(done), analysed, ok, conflicts, real_errors, fallbacks, skipped,
    )

    # Advance only over documents actually processed, so an interrupted batch
    # is resumed rather than skipped.
    return next_cursor


def main() -> int:
    log.info(
        "starting llm-analyzer  source=%s  target=%s*  min_score=%s  interval=%ss  batch=%s  severity=%s",
        SOURCE_INDEX, TARGET_PREFIX, MIN_SCORE, POLL_INTERVAL, BATCH_SIZE,
        "model" if ASK_SEVERITY else "derive",
    )
    try:
        provider = providers.build_provider()
    except providers.ProviderError as e:
        log.error("provider configuration error: %s", e)
        return 1
    log.info("llm provider=%s model=%s", provider.name, provider.model)

    es = Elasticsearch(ES_HOST, request_timeout=30)
    _ensure_template(es)
    _ensure_field_mappings(es)

    cursor = _load_cursor()
    log.info("resume cursor: %s", cursor or f"(none, bootstrap window={BOOTSTRAP_WINDOW})")

    while _running:
        try:
            new_cursor = _poll_once(es, provider, cursor)
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
