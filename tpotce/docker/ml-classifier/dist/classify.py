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

# ── index template ────────────────────────────────────────────────────────
# `ml-analysis-*` 는 하루 한 인덱스로 새로 만들어진다. 템플릿이 없으면 각 인덱스가
# "그날 처음 들어온 문서"의 모양대로 동적 매핑을 잡는데, 그러면 두 가지가 조용히
# 깨진다.
#
#   1. 날짜별로 타입이 갈린다. 소비자는 `ml-analysis-*` 로 한꺼번에 조회하므로
#      하루는 되고 하루는 안 되는 상태가 된다.
#   2. 숫자 필드에 문자열이 한 번 들어오면 그 인덱스에서 영구히 text 가 된다.
#      `dest_port` 가 그렇게 되면 포트 집계가 "Fielddata is disabled" 로 실패하고,
#      백엔드와 threat-console 은 그 예외를 삼켜 빈 차트를 그린다. 값이 틀린 게
#      아니라 화면이 비는 것이라 아무도 눈치채지 못한다 — 실제로 겪은 실패다.
#      타입을 못 박아두면 ES 가 색인 단계에서 걸러준다. `"23.0"` 처럼 고칠 수
#      있는 값은 숫자 23 으로 강제변환해 색인하고(`_source` 에는 원문이 남는다),
#      `"abc"` 처럼 고칠 수 없는 값은 document_parsing_exception 으로 거부해
#      로그에 남긴다. 어느 쪽이든 필드가 text 로 굳어 집계가 죽는 일은 없다.
#
# 타입은 "더 좋은 것"이 아니라 **지금 인덱스에 있는 모양 그대로** 적는다.
# 예컨대 `src_ip` 를 `ip` 로 올리면 오늘 인덱스는 text, 내일 인덱스는 ip 가 되어
# 오히려 `ml-analysis-*` 가 날짜별로 갈린다. 타입을 올리려면 전체 reindex 가
# 함께 가야 한다.
#
# 소비자가 `ml_label.keyword` · `honeypot.keyword` · `model_used.keyword` 로
# 집계하므로 이 필드들은 text+keyword 형태를 유지해야 한다. 바로 keyword 로
# 바꾸면 하위필드가 사라져 집계가 깨진다.
TEMPLATE_NAME = os.getenv("ES_TEMPLATE_NAME", "ml-analysis")

# 보존 기간(일). 0 이면 보존 정책을 아예 걸지 않는다 — **기본값이 0 인 이유가
# 중요하다.** 이 저장소의 시연 데이터는 2026-04~05 의 보관 로그이고, 보고서의
# 모든 수치가 거기서 나온다. 짧은 보존을 켜두면 어느 날 조용히 지워지고, 그때는
# 화면이 비는 게 아니라 **숫자가 달라진다** — 원인을 찾기도 어렵다.
#
# 라이브로 운영할 때 켠다. ILM 의 나이는 **인덱스 생성 시각** 기준이지 인덱스
# 이름의 날짜가 아니다(이름은 2026.04.27 이어도 재색인한 날 만들어졌으면 그날이
# 0일째다). 보관 로그를 적재한 장비에서 켜면, 켠 날로부터 N일 뒤에 사라진다.
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "0"))
ILM_POLICY_NAME = os.getenv("ES_ILM_POLICY", f"{TEMPLATE_NAME}-retention")

_TEXT_KW = {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}}

def _template_settings() -> dict:
    settings = {"number_of_shards": 1, "number_of_replicas": 0}
    if RETENTION_DAYS > 0:
        settings["index.lifecycle.name"] = ILM_POLICY_NAME
    return settings


INDEX_TEMPLATE = {
    "index_patterns": [f"{TARGET_PREFIX}*"],
    "template": {
        "settings": _template_settings(),
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "src_ip": _TEXT_KW,
                "dest_ip": _TEXT_KW,
                "dest_port": {"type": "long"},
                "honeypot": _TEXT_KW,
                "ml_label": _TEXT_KW,
                "ml_label_raw": _TEXT_KW,
                "ml_is_attack": {"type": "boolean"},
                "ml_dissent": {"type": "boolean"},
                "ml_multi_conf": {"type": "float"},
                "mitre_score": {"type": "long"},
                "mitre_technique": _TEXT_KW,
                "model_used": _TEXT_KW,
                "model_version": _TEXT_KW,
                "source_doc_id": _TEXT_KW,
                "source_index": _TEXT_KW,
            }
        },
    },
}


def _ensure_ilm(es: Elasticsearch) -> None:
    """보존 정책을 만들고 기존 인덱스에도 붙인다.

    **인덱스 템플릿만 고치면 이미 만들어진 인덱스는 계속 남는다** — 템플릿은
    생성 시점에만 적용된다. `ml_label_raw` 가 text 로 남아 집계가 전량 실패한
    것과 같은 함정이라(§23-4), 여기서도 기존 인덱스에 직접 밀어 넣는다.
    """
    if RETENTION_DAYS <= 0:
        log.info("retention disabled (RETENTION_DAYS=0) — %s* 는 지워지지 않는다",
                 TARGET_PREFIX)
        return

    policy = {
        "policy": {
            "phases": {
                # rollover 는 쓰지 않는다. 인덱스가 날짜별로 이미 갈려 있고
                # 하루치가 작아서, 굴릴 이유가 없다.
                "hot": {"actions": {}},
                "delete": {
                    "min_age": f"{RETENTION_DAYS}d",
                    "actions": {"delete": {}},
                },
            }
        }
    }
    try:
        es.ilm.put_lifecycle(name=ILM_POLICY_NAME, body=policy)
        log.info("ILM policy %r: %s* 는 %d일 뒤 삭제",
                 ILM_POLICY_NAME, TARGET_PREFIX, RETENTION_DAYS)
    except Exception as e:  # noqa: BLE001
        log.warning("could not put ILM policy (continuing): %s", e)
        return

    try:
        es.indices.put_settings(
            index=f"{TARGET_PREFIX}*",
            body={"index.lifecycle.name": ILM_POLICY_NAME},
            ignore_unavailable=True,
        )
        log.info("기존 %s* 인덱스에도 보존 정책 적용", TARGET_PREFIX)
    except Exception as e:  # noqa: BLE001
        log.warning("could not apply ILM to existing indices: %s", e)


def _ensure_template(es: Elasticsearch) -> None:
    try:
        es.indices.put_index_template(name=TEMPLATE_NAME, body=INDEX_TEMPLATE)
        log.info("index template %r ensured for %s*", TEMPLATE_NAME, TARGET_PREFIX)
    except Exception as e:  # noqa: BLE001
        # 치명적이지 않다. 템플릿이 없어도 색인은 되고 집계만 나빠지므로,
        # 죽이지 말고 경고만 남긴다.
        log.warning("could not put index template (continuing): %s", e)


def _ensure_field_mappings(es: Elasticsearch) -> None:
    """이미 만들어진 인덱스에도 템플릿의 필드 타입을 밀어 넣는다.

    인덱스 템플릿은 **인덱스가 만들어질 때만** 적용된다. 템플릿에 필드를 새로
    추가해도(`ml_label_raw`, `ml_dissent` 가 그랬다) 그 전에 만들어진 인덱스로
    들어가는 문서는 동적 매핑을 타고, keyword 여야 할 것이 text 가 되어 집계가
    조용히 실패한다. 템플릿을 넣은 이유가 바로 그건데 같은 구멍이 남는 셈이라
    여기서 함께 막는다. 기존 매핑에 필드를 더하는 것은 허용되고, 타입이 충돌하는
    필드는 숨기지 말고 보고한다 — 그건 reindex 가 필요한 경우다.
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
HEARTBEAT_PATH = STATE_DIR / "heartbeat"
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


def _touch_heartbeat() -> None:
    """살아 있다는 표시. 한 바퀴 돌 때마다 남긴다.

    커서 파일로는 대신할 수 없다. 커서는 **새 문서를 처리했을 때만** 움직이므로,
    밀린 게 없어 조용한 정상 상태와 프로세스가 멈춘 상태가 구분되지 않는다.
    §16·§20 에서 두 번 당한 그 모양이다 — 침묵이 정상인지 고장인지 알 수 없으면
    감시가 아니다. 이 파일은 할 일이 없어도 갱신된다.
    """
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        HEARTBEAT_PATH.write_text(datetime.now(timezone.utc).isoformat())
    except OSError as e:
        log.warning("heartbeat write failed: %s", e)


def _save_cursor(values: list) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    CURSOR_PATH.write_text(json.dumps(values))


def _predict_proba_batch(multi, X):
    """배치 전체의 확률을 구한다. 실패하면 행 단위로 물러선다.

    한 번에 넣는 이유: predict_proba 는 호출마다 파이썬↔부스터 경계를 넘고
    입력 검증과 스레드 준비를 다시 한다. 그 고정비가 행 수보다 크게 먹혀서,
    같은 1,000건이라도 1,000번 부르는 것과 1번 부르는 것의 차이가 크다.

    실패 시 행 단위로 물러서는 이유: 배치로 바꾸면서 예외 범위도 배치 전체로
    넓어졌다. 문서 하나가 이상해서 배치 1,000건이 통째로 규칙 전용이 되면
    **교차검증이 조용히 사라진다** — 그 1,000건은 ml_label_raw 가 비어 있고,
    화면에는 아무 경고도 뜨지 않는다. 문제 있는 행만 버린다.
    """
    try:
        return multi.predict_proba(X)
    except Exception as e:  # noqa: BLE001
        log.warning("batch classify failed (%s) — falling back to per-row", e)

    out = []
    for i in range(len(X)):
        try:
            out.append(multi.predict_proba(X[i:i + 1])[0])
        except Exception as e:  # noqa: BLE001
            log.warning("classify failed for row %d: %s", i, e)
            out.append(None)      # 이 건만 규칙 전용으로 간다
    return out


def _decide(doc: dict, proba, classes) -> dict:
    # 규칙이 기준선이다. 라벨은 규칙에서 나오고, 모델은 그 위에서 교차검증한다.
    #
    # 예전에는 모델이 있으면 라벨을 통째로 덮어썼고, 신뢰도가 낮으면
    # "Normal"(무해)로 바꿨다. 그러면 **모델이 처음 보는 공격일수록 무해로
    # 표시되어** 고위험 파이프라인에서 사라진다 — 보안 도구가 가면 안 되는
    # 방향이다. 지금은 모델이 규칙을 뒤집지 못하고, 대신
    #   · 신뢰도(ml_multi_conf)
    #   · 규칙과 다른 판단(ml_dissent / ml_label_raw)
    # 를 남겨 검토 대상을 드러내는 역할을 한다.
    label = rule_label.label_from_doc(doc)
    multi_conf = 100.0
    model_used = "rule"
    ml_raw = None
    dissent = False

    if proba is not None:
        idx = int(np.argmax(proba))
        ml_raw = str(classes[idx])
        max_prob = float(proba[idx])
        multi_conf = round(max_prob * 100, 1)

        if max_prob < CONF_THRESHOLD:
            # 저신뢰 = "모르겠다". 라벨을 바꿀 근거가 못 된다.
            model_used = "rule(low-conf)"
        elif ml_raw == label:
            model_used = "ml+rule"      # 합의 — 이 건은 신뢰도가 높다
        else:
            model_used = "rule(dissent)"
            dissent = True              # 사람이 볼 만한 건

    is_atk = rule_label.is_attack(label)
    score = mitre.score_for(label) if is_atk else 0
    return {
        "ml_label": label,
        "ml_is_attack": bool(is_atk),
        "ml_multi_conf": multi_conf,
        "ml_label_raw": ml_raw,      # 모델의 원 판단(규칙과 다를 수 있다)
        "ml_dissent": dissent,       # 규칙과 어긋난 건 → 검토 큐
        "mitre_score": score,
        "mitre_technique": mitre.technique_for(label),
        "model_used": model_used,
        "model_version": MODEL_VERSION,
    }


def _classify_docs(docs: list, multi, encoders: dict) -> list:
    """문서 묶음을 한 번에 분류한다. 순서는 입력과 같다."""
    if not docs:
        return []

    feats = [feature_extract.extract(d, encoders) for d in docs]
    probas = [None] * len(docs)
    classes = None

    if multi is not None:
        classes = multi.classes_
        probas = _predict_proba_batch(multi, np.array(feats))

    return [_decide(doc, probas[i], classes) for i, doc in enumerate(docs)]


def _classify_doc(doc: dict, multi, encoders: dict) -> dict:
    """문서 한 건. 배치 경로와 같은 판단을 거치도록 위임한다."""
    return _classify_docs([doc], multi, encoders)[0]


def _target_index_for(ts_iso: str) -> str:
    try:
        d = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        d = datetime.now(timezone.utc)
    return f"{TARGET_PREFIX}{d.strftime('%Y.%m.%d')}"


def _build_action(src_doc: dict, src_index: str, src_id: str, result: dict) -> dict:
    ts = src_doc.get("@timestamp") or datetime.now(timezone.utc).isoformat()
    return {
        # index(덮어쓰기)다. _id 가 원본 문서 _id 로 결정론적이므로 재실행은
        # 멱등하다. create 였을 때는 모델을 교체하고 커서를 되감아도 기존
        # 문서가 전부 version_conflict 로 거부되어 ml_label_raw 가 옛 모델의
        # 판단으로 남았다 — 재분류라는 동작 자체가 성립하지 않았다.
        "_op_type": "index",
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

    Returns ``(cursor, n_hits)`` — the cursor for the next call (last hit's
    ``sort`` array, or the input cursor unchanged if no new docs were found)
    and how many docs this cycle handled. The caller uses the count to tell a
    full batch (backlog remains) from a short one (caught up).
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
        return cursor, 0

    results = _classify_docs([h["_source"] for h in hits], multi, encoders)
    actions = [
        _build_action(hit["_source"], hit["_index"], hit["_id"], result)
        for hit, result in zip(hits, results)
    ]
    ok, errors = helpers.bulk(es, actions, raise_on_error=False, raise_on_exception=False)
    log.info("polled=%d, indexed=%d, errors=%d", len(hits), ok, len(errors) if errors else 0)

    return hits[-1].get("sort", cursor), len(hits)


def main() -> int:
    log.info("starting ml-classifier  source=%s  target=%s*  interval=%ss",
             SOURCE_INDEX, TARGET_PREFIX, POLL_INTERVAL)
    multi, encoders = _load_models()
    last_sig = _model_signature()
    es = Elasticsearch(ES_HOST, request_timeout=30)
    _ensure_ilm(es)
    _ensure_template(es)
    _ensure_field_mappings(es)

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

        backlog = False
        try:
            new_cursor, n = _poll_once(es, cursor, multi, encoders)
            if new_cursor and new_cursor != cursor:
                cursor = new_cursor
                _save_cursor(cursor)
            # 배치가 가득 찼다 = 아직 밀린 문서가 있다. 그때까지 POLL_INTERVAL
            # 을 지키면 보관 로그 100만 건을 훑는 데 1,029배치 × 30초 = 8.6시간이
            # 걸린다. 밀려 있는 동안은 쉬지 않고 이어서 돈다.
            backlog = n >= BATCH_SIZE
        except Exception as e:  # noqa: BLE001
            log.exception("poll cycle failed: %s", e)
        _touch_heartbeat()

        if backlog:
            continue
        for _ in range(POLL_INTERVAL):
            if not _running:
                break
            time.sleep(1)

    log.info("shut down cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
