"""Threat Console (Korean) — Unified frontend for ml-classifier + llm-analyzer.

Lightweight Flask service that:
  * serves a single-page Korean UI (overview / ML / LLM / reports)
  * proxies aggregation queries against Elasticsearch (read-only)
  * generates Korean-formatted PDF reports from llm-analysis-*

Environment:
    ES_HOST           Elasticsearch URL (default: http://elasticsearch:9200)
    REPORT_DIR        Directory to store generated PDFs (default: /data/threat-console/reports)
    LISTEN_PORT       HTTP listen port inside container (default: 8080)
"""
from __future__ import annotations

import csv
import io
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from elasticsearch import Elasticsearch
from flask import Flask, Response, jsonify, request, send_file, send_from_directory
from jinja2 import Environment, FileSystemLoader, select_autoescape

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
REPORT_DIR = Path(os.getenv("REPORT_DIR", "/data/threat-console/reports"))
TRAIN_DIR  = Path(os.getenv("TRAIN_DIR",  "/data/threat-console/training"))
# Where ml-classifier loads .pkl from (shared volume on the host)
MODEL_ACTIVE_DIR = Path(os.getenv("MODEL_ACTIVE_DIR", "/data/ml-classifier/models"))
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))

REPORT_DIR.mkdir(parents=True, exist_ok=True)
TRAIN_DIR.mkdir(parents=True, exist_ok=True)
(TRAIN_DIR / "datasets").mkdir(parents=True, exist_ok=True)
(TRAIN_DIR / "models").mkdir(parents=True, exist_ok=True)
(TRAIN_DIR / "uploads").mkdir(parents=True, exist_ok=True)

app = Flask(
    __name__,
    static_folder="static",
    static_url_path="/static",
)
es = Elasticsearch(ES_HOST, request_timeout=15)

_jinja = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
    autoescape=select_autoescape(["html", "xml"]),
)


def _safe_search(index: str, body: dict) -> dict:
    body = {**body, "track_total_hits": True}
    try:
        return es.search(index=index, body=body, ignore_unavailable=True).body
    except Exception as e:  # noqa: BLE001
        app.logger.warning("ES search failed on %s: %s", index, e)
        return {"hits": {"hits": []}, "aggregations": {}}


# ── Static UI ─────────────────────────────────────────────────────────────
@app.get("/")
def index() -> object:
    return send_from_directory(app.static_folder, "index.html")


# ── API: 24h overview cards ──────────────────────────────────────────────
@app.get("/api/overview")
def overview() -> object:
    since = "now-24h"

    # Total events (raw honeypot logs)
    raw = _safe_search("logstash-*", {"size": 0, "query": {"range": {"@timestamp": {"gte": since}}}})
    total_events = raw.get("hits", {}).get("total", {}).get("value", 0)

    # Classified attacks
    ml = _safe_search("ml-analysis-*", {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since}}},
            {"term": {"ml_is_attack": True}},
        ]}},
    })
    total_attacks = ml.get("hits", {}).get("total", {}).get("value", 0)

    # High-risk (mitre_score >= 70)
    high = _safe_search("ml-analysis-*", {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since}}},
            {"range": {"mitre_score": {"gte": 70}}},
        ]}},
    })
    high_risk = high.get("hits", {}).get("total", {}).get("value", 0)

    # LLM analyzed
    llm = _safe_search("llm-analysis-*", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": since}}},
    })
    llm_total = llm.get("hits", {}).get("total", {}).get("value", 0)

    return jsonify({
        "since": since,
        "total_events": total_events,
        "total_attacks": total_attacks,
        "high_risk": high_risk,
        "llm_analyzed": llm_total,
    })


# ── API: ML classification breakdown ──────────────────────────────────────
@app.get("/api/ml-stats")
def ml_stats() -> object:
    since = request.args.get("since", "now-24h")
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": since}}},
        "aggs": {
            "labels":     {"terms": {"field": "ml_label.keyword", "size": 10}},
            "honeypots":  {"terms": {"field": "honeypot.keyword", "size": 15}},
            "by_hour":    {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}},
            "score_dist": {"histogram": {"field": "mitre_score", "interval": 10, "min_doc_count": 0}},
            "model_used": {"terms": {"field": "model_used.keyword", "size": 5}},
        },
    }
    r = _safe_search("ml-analysis-*", body)
    aggs = r.get("aggregations", {})
    return jsonify({
        "labels":     [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("labels", {}).get("buckets", [])],
        "honeypots":  [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("honeypots", {}).get("buckets", [])],
        "by_hour":    [{"ts": b["key_as_string"], "count": b["doc_count"]} for b in aggs.get("by_hour", {}).get("buckets", [])],
        "score_dist": [{"score": b["key"], "count": b["doc_count"]} for b in aggs.get("score_dist", {}).get("buckets", [])],
        "model_used": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("model_used", {}).get("buckets", [])],
    })


# ── API: recent LLM analyses ──────────────────────────────────────────────
@app.get("/api/llm-recent")
def llm_recent() -> object:
    since = request.args.get("since", "now-7d")
    size = min(int(request.args.get("size", "30")), 200)
    severity = request.args.get("severity")  # LOW/MEDIUM/HIGH/CRITICAL or None

    filters = [{"range": {"@timestamp": {"gte": since}}}]
    if severity:
        filters.append({"term": {"severity": severity}})

    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters}},
        "_source": ["@timestamp", "src_ip", "honeypot", "ml_label",
                    "mitre_score", "risk_score", "severity",
                    "summary_ko", "solution_ko", "ttp_inferred"],
    }
    r = _safe_search("llm-analysis-*", body)
    items = [h["_source"] for h in r.get("hits", {}).get("hits", [])]
    return jsonify({"items": items, "count": len(items)})


# ── API: severity distribution ────────────────────────────────────────────
@app.get("/api/llm-stats")
def llm_stats() -> object:
    since = request.args.get("since", "now-7d")
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": since}}},
        "aggs": {
            "severity":  {"terms": {"field": "severity", "size": 4}},
            "honeypots": {"terms": {"field": "honeypot.keyword", "size": 10}},
            "risk_dist": {"histogram": {"field": "risk_score", "interval": 1, "min_doc_count": 0}},
        },
    }
    r = _safe_search("llm-analysis-*", body)
    aggs = r.get("aggregations", {})
    return jsonify({
        "severity":  [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("severity", {}).get("buckets", [])],
        "honeypots": [{"key": b["key"], "count": b["doc_count"]} for b in aggs.get("honeypots", {}).get("buckets", [])],
        "risk_dist": [{"score": b["key"], "count": b["doc_count"]} for b in aggs.get("risk_dist", {}).get("buckets", [])],
    })


# ── API: generate PDF report ──────────────────────────────────────────────
@app.post("/api/report")
def generate_report() -> object:
    since = request.json.get("since", "now-7d") if request.is_json else "now-7d"

    # Aggregate data
    overview_data = overview().get_json()
    ml_data = _safe_search("ml-analysis-*", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": since}}},
        "aggs": {
            "labels":    {"terms": {"field": "ml_label.keyword", "size": 10}},
            "honeypots": {"terms": {"field": "honeypot.keyword", "size": 10}},
        },
    })
    llm_data = _safe_search("llm-analysis-*", {
        "size": 50,
        "sort": [{"risk_score": {"order": "desc"}}],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since}}},
            {"terms": {"severity": ["HIGH", "CRITICAL"]}},
        ]}},
        "_source": ["@timestamp", "src_ip", "honeypot", "ml_label",
                    "risk_score", "severity", "summary_ko", "solution_ko",
                    "ttp_inferred", "mitre_score"],
    })
    sev_agg = _safe_search("llm-analysis-*", {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": since}}},
        "aggs": {"severity": {"terms": {"field": "severity", "size": 4}}},
    })

    ctx = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "since": since,
        "overview": overview_data,
        "label_buckets": ml_data.get("aggregations", {}).get("labels", {}).get("buckets", []),
        "honeypot_buckets": ml_data.get("aggregations", {}).get("honeypots", {}).get("buckets", []),
        "severity_buckets": sev_agg.get("aggregations", {}).get("severity", {}).get("buckets", []),
        "high_risk_events": [h["_source"] for h in llm_data.get("hits", {}).get("hits", [])],
    }

    html = _jinja.get_template("ko_report.html.j2").render(**ctx)

    # Render PDF
    try:
        from weasyprint import HTML
    except ImportError as e:
        return jsonify({"error": f"weasyprint not installed: {e}"}), 500

    report_id = uuid.uuid4().hex[:12]
    pdf_path = REPORT_DIR / f"report_{report_id}.pdf"
    HTML(string=html).write_pdf(str(pdf_path))

    return jsonify({
        "report_id": report_id,
        "path": str(pdf_path),
        "size_bytes": pdf_path.stat().st_size,
        "url": f"/threat-console/api/report/{report_id}",
    })


@app.get("/api/report/<report_id>")
def download_report(report_id: str) -> object:
    if not report_id.replace("-", "").isalnum():
        return jsonify({"error": "invalid id"}), 400
    pdf_path = REPORT_DIR / f"report_{report_id}.pdf"
    if not pdf_path.exists():
        return jsonify({"error": "not found"}), 404
    return send_file(str(pdf_path), as_attachment=True,
                     download_name=f"threat-report-{report_id}.pdf")


# ── API: CSV / JSON export of LLM analyses ───────────────────────────────
@app.get("/api/export/llm")
def export_llm() -> object:
    since = request.args.get("since", "now-7d")
    fmt   = request.args.get("format", "csv").lower()
    body = {
        "size": 5000,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"range": {"@timestamp": {"gte": since}}},
        "_source": ["@timestamp", "src_ip", "honeypot", "ml_label",
                    "mitre_score", "risk_score", "severity",
                    "summary_ko", "solution_ko", "ttp_inferred"],
    }
    r = _safe_search("llm-analysis-*", body)
    rows = [h["_source"] for h in r.get("hits", {}).get("hits", [])]

    if fmt == "json":
        return Response(
            response="[\n" + ",\n".join(__import__("json").dumps(x, ensure_ascii=False) for x in rows) + "\n]",
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="llm-analysis-{since.replace("-","")}.json"'},
        )

    cols = ["@timestamp", "severity", "risk_score", "mitre_score",
            "src_ip", "honeypot", "ml_label",
            "summary_ko", "solution_ko", "ttp_inferred"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r_ in rows:
        ttp = ";".join(r_.get("ttp_inferred") or [])
        w.writerow([r_.get(c) if c != "ttp_inferred" else ttp for c in cols])
    return Response(
        response="﻿" + buf.getvalue(),  # BOM for Excel Korean
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="llm-analysis-{since.replace("-","")}.csv"'},
    )


@app.get("/api/export/ml")
def export_ml() -> object:
    since = request.args.get("since", "now-7d")
    fmt   = request.args.get("format", "csv").lower()
    body = {
        "size": 10000,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"range": {"@timestamp": {"gte": since}}},
        "_source": ["@timestamp", "src_ip", "dest_port", "honeypot",
                    "ml_label", "ml_is_attack", "ml_multi_conf",
                    "mitre_score", "mitre_technique", "model_used", "model_version"],
    }
    r = _safe_search("ml-analysis-*", body)
    rows = [h["_source"] for h in r.get("hits", {}).get("hits", [])]

    if fmt == "json":
        return Response(
            response="[\n" + ",\n".join(__import__("json").dumps(x, ensure_ascii=False) for x in rows) + "\n]",
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="ml-analysis-{since.replace("-","")}.json"'},
        )

    cols = ["@timestamp", "ml_label", "ml_is_attack", "ml_multi_conf",
            "mitre_score", "mitre_technique", "src_ip", "dest_port",
            "honeypot", "model_used", "model_version"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r_ in rows:
        w.writerow([r_.get(c) for c in cols])
    return Response(
        response="﻿" + buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="ml-analysis-{since.replace("-","")}.csv"'},
    )


@app.get("/api/reports")
def list_reports() -> object:
    items = []
    for p in sorted(REPORT_DIR.glob("report_*.pdf"), key=lambda x: x.stat().st_mtime, reverse=True)[:50]:
        items.append({
            "id": p.stem.replace("report_", ""),
            "size_bytes": p.stat().st_size,
            "created_at": datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(),
        })
    return jsonify({"items": items})


# ── Training pipeline automation ─────────────────────────────────────────
import json as _json
import shutil
import subprocess
import threading
import time as _time

# In-memory job state. Single-tenant so dict is fine.
_JOBS: dict[str, dict] = {}
_JOB_LOCK = threading.Lock()


def _set_job(job_id: str, **fields) -> None:
    with _JOB_LOCK:
        _JOBS.setdefault(job_id, {"id": job_id})
        _JOBS[job_id].update(fields)
        _JOBS[job_id]["updated_at"] = datetime.now(timezone.utc).isoformat()


def _get_job(job_id: str) -> dict | None:
    with _JOB_LOCK:
        return dict(_JOBS.get(job_id) or {}) or None


def _run_subprocess(job_id: str, cmd: list[str], cwd: Path, on_done) -> None:
    _set_job(job_id, status="running", log=[], started_at=datetime.now(timezone.utc).isoformat())
    try:
        proc = subprocess.Popen(cmd, cwd=str(cwd),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        log_lines: list[str] = []
        for line in proc.stdout:  # type: ignore[union-attr]
            line = line.rstrip()
            log_lines.append(line)
            if len(log_lines) > 400:
                log_lines = log_lines[-300:]
            _set_job(job_id, log=list(log_lines))
        proc.wait()
        if proc.returncode == 0:
            on_done(job_id, log_lines)
            _set_job(job_id, status="success",
                     finished_at=datetime.now(timezone.utc).isoformat())
        else:
            _set_job(job_id, status="failed", returncode=proc.returncode,
                     finished_at=datetime.now(timezone.utc).isoformat())
    except Exception as e:  # noqa: BLE001
        _set_job(job_id, status="failed", error=str(e),
                 finished_at=datetime.now(timezone.utc).isoformat())


# Path to the training pipeline shipped with ml-classifier
TRAINING_SRC = Path(os.getenv("TRAINING_SRC", "/opt/ml-classifier-training"))


@app.post("/api/train/dataset")
def train_dataset() -> object:
    """Build a dataset from ES (auto mode).

    Optional body fields:
        normal_n   int  — normal rows to fetch from NSL-KDD open dataset (0 = disabled).
                          Default: same as balance_n (one Normal row per target class size).
    balance_n  int  — cap each attack class at this many rows (downsample majority).
                          Recommended 8000–10000. Default: 10000.
    """
    body = request.get_json(silent=True) or {}
    since     = body.get("since", "now-3h")
    max_docs  = int(body.get("max", 30000))
    balance_n = max(0, int(body.get("balance_n", 10000)))
    # Default normal_n = balance_n (one Normal class == same size as each attack class)
    normal_n  = max(0, int(body.get("normal_n", balance_n)))

    job_id  = f"ds-{uuid.uuid4().hex[:8]}"
    (TRAIN_DIR / "datasets").mkdir(parents=True, exist_ok=True)
    out_csv = TRAIN_DIR / "datasets" / f"{job_id}.csv"
    out_enc = TRAIN_DIR / "datasets" / f"{job_id}.encoders.json"

    # Step 1: pull honeypot attack docs from ES
    cmd = [
        "python3", str(TRAINING_SRC / "build_dataset.py"),
        "--es", ES_HOST,
        "--since", since,
        "--max", str(max_docs),
        "--out", str(out_csv),
        "--encoders-out", str(out_enc),
    ]
    if balance_n > 0:
        cmd += ["--balance-n", str(balance_n)]

    # Step 2: fetch NSL-KDD normal traffic and merge in.
    # fetch_normal.py downloads KDDTrain+.txt once and caches it locally.
    normal_csv_path = None
    if normal_n > 0:
        normal_csv_path = TRAIN_DIR / "datasets" / f"{job_id}-normal.csv"
        kdd_cache = TRAIN_DIR / "datasets" / "KDDTrain+.txt"
        fetch_cmd = [
            "python3", str(TRAINING_SRC / "fetch_normal.py"),
            "--n", str(normal_n),
            "--out", str(normal_csv_path),
            "--encoders", str(out_enc),
            "--cache", str(kdd_cache),
        ]
        # fetch_normal runs AFTER build_dataset (needs encoders.json to align protocol coding)
        # So we inject it into the done-callback, not here.

    def _done(jid, lines):
        _set_job(jid, dataset_csv=str(out_csv), encoders_json=str(out_enc))
        # Fetch NSL-KDD normal rows and re-merge into the CSV
        if normal_n > 0 and normal_csv_path is not None:
            try:
                import subprocess as _sp
                _sp.run(fetch_cmd, cwd=str(TRAINING_SRC), check=True,
                        capture_output=True, text=True, timeout=120)
                # Append normal rows to the existing CSV
                with open(str(normal_csv_path), encoding="utf-8") as nf:
                    reader = __import__("csv").reader(nf)
                    next(reader)  # skip header
                    normal_data = list(reader)
                with open(str(out_csv), "a", encoding="utf-8", newline="") as of:
                    writer = __import__("csv").writer(of)
                    writer.writerows(normal_data)
                _set_job(jid, normal_n=len(normal_data))
            except Exception as e:
                _set_job(jid, normal_warning=str(e))

    _set_job(job_id, kind="dataset", status="queued",
             since=since, max=max_docs, balance_n=balance_n, normal_n=normal_n)
    threading.Thread(target=_run_subprocess,
                     args=(job_id, cmd, TRAINING_SRC, _done), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.post("/api/train/upload")
def train_upload() -> object:
    """Receive uploaded train.csv and (optional) test.csv."""
    if "train" not in request.files:
        return jsonify({"error": "field 'train' required"}), 400
    job_id = f"up-{uuid.uuid4().hex[:8]}"
    train_path = TRAIN_DIR / "uploads" / f"{job_id}-train.csv"
    request.files["train"].save(str(train_path))
    test_path = None
    if "test" in request.files and request.files["test"].filename:
        test_path = TRAIN_DIR / "uploads" / f"{job_id}-test.csv"
        request.files["test"].save(str(test_path))
    enc_path = None
    if "encoders" in request.files and request.files["encoders"].filename:
        enc_path = TRAIN_DIR / "uploads" / f"{job_id}-encoders.json"
        request.files["encoders"].save(str(enc_path))
    _set_job(job_id, kind="upload", status="success",
             dataset_csv=str(train_path),
             test_csv=str(test_path) if test_path else None,
             encoders_json=str(enc_path) if enc_path else None,
             finished_at=datetime.now(timezone.utc).isoformat())
    return jsonify({"job_id": job_id, "train": str(train_path),
                    "test": str(test_path) if test_path else None})


@app.post("/api/train/start")
def train_start() -> object:
    """Train models from a dataset created by /api/train/dataset or /api/train/upload.

    Optional body fields:
        smote  bool  — apply SMOTE to balance minority classes before training
                       (MDPI IDS 2024: best combined with class_weight=balanced).
        no_cv  bool  — skip stratified 5-fold CV (faster, less reliable metrics).
    """
    body = request.get_json(silent=True) or {}
    src_id = body.get("source_job_id")
    src = _get_job(src_id) if src_id else None
    if not src or not src.get("dataset_csv"):
        return jsonify({"error": "source_job_id missing or no dataset"}), 400

    use_smote = bool(body.get("smote", False))
    no_cv     = bool(body.get("no_cv", False))

    job_id = f"tr-{uuid.uuid4().hex[:8]}"
    out_dir = TRAIN_DIR / "models" / job_id
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = ["python3", str(TRAINING_SRC / "train.py"),
           "--out-dir", str(out_dir)]
    if src.get("test_csv"):
        cmd += ["--train-csv", src["dataset_csv"], "--test-csv", src["test_csv"]]
    else:
        cmd += ["--csv", src["dataset_csv"]]
    if src.get("encoders_json"):
        cmd += ["--encoders", src["encoders_json"]]
    if use_smote:
        cmd += ["--smote"]
    if no_cv:
        cmd += ["--no-cv"]

    def _done(jid, lines):
        metrics_path = out_dir / "metrics.json"
        metrics = {}
        if metrics_path.exists():
            try:
                metrics = _json.loads(metrics_path.read_text())
            except (ValueError, OSError):
                pass
        _set_job(jid, model_dir=str(out_dir), metrics=metrics)

    _set_job(job_id, kind="train", status="queued", source_job_id=src_id)
    threading.Thread(target=_run_subprocess,
                     args=(job_id, cmd, TRAINING_SRC, _done), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.post("/api/train/activate")
def train_activate() -> object:
    """Copy a trained model into ml-classifier's active directory.
    ml-classifier hot-reloads when the .pkl mtime changes."""
    body = request.get_json(silent=True) or {}
    src_id = body.get("train_job_id")
    src = _get_job(src_id) if src_id else None
    if not src or src.get("status") != "success" or not src.get("model_dir"):
        return jsonify({"error": "train job not finished or missing"}), 400

    src_dir = Path(src["model_dir"])
    MODEL_ACTIVE_DIR.mkdir(parents=True, exist_ok=True)
    copied = []
    for name in ("multi_model.pkl", "encoders.json"):
        s = src_dir / name
        if s.exists():
            shutil.copyfile(str(s), str(MODEL_ACTIVE_DIR / name))
            copied.append(name)
    return jsonify({"activated_from": str(src_dir),
                    "active_dir": str(MODEL_ACTIVE_DIR),
                    "copied": copied})


@app.post("/api/model/upload")
def model_upload() -> object:
    """Upload a pre-trained model directly into ml-classifier's active dir (BYOM).

    Skips the dataset/train flow for users who already have a model trained
    elsewhere against the 16-feature schema in feature_extract.py.  The pkl
    is loaded once to verify it exposes ``predict`` and ``predict_proba``;
    any joblib-compatible classifier is accepted (sklearn, lightgbm, etc.).
    ml-classifier hot-reloads when ``multi_model.pkl`` mtime changes.
    """
    if "model" not in request.files or not request.files["model"].filename:
        return jsonify({"error": "field 'model' (multi_model.pkl) is required"}), 400

    import joblib
    import tempfile

    MODEL_ACTIVE_DIR.mkdir(parents=True, exist_ok=True)
    # Staging dir lives inside MODEL_ACTIVE_DIR so the final shutil.move is a
    # rename within the same filesystem (atomic) and we don't need write
    # permission on /data/ml-classifier/ itself, which is read-only when only
    # the models subdir is bind-mounted.
    staging = Path(tempfile.mkdtemp(prefix=".byom-", dir=str(MODEL_ACTIVE_DIR)))
    try:
        tmp_pkl = staging / "multi_model.pkl"
        request.files["model"].save(str(tmp_pkl))
        try:
            mdl = joblib.load(str(tmp_pkl))
        except Exception as e:  # noqa: BLE001
            return jsonify({"error": f"pickle load failed: {e}"}), 400
        if not (hasattr(mdl, "predict") and hasattr(mdl, "predict_proba")):
            return jsonify({"error": "model must implement predict + predict_proba"}), 400

        tmp_enc = None
        if "encoders" in request.files and request.files["encoders"].filename:
            tmp_enc = staging / "encoders.json"
            request.files["encoders"].save(str(tmp_enc))
            try:
                _json.loads(tmp_enc.read_text())
            except (ValueError, OSError) as e:
                return jsonify({"error": f"encoders.json invalid: {e}"}), 400

        # Validation passed — atomically move into active dir
        copied = []
        shutil.move(str(tmp_pkl), str(MODEL_ACTIVE_DIR / "multi_model.pkl"))
        copied.append("multi_model.pkl")
        if tmp_enc is not None:
            shutil.move(str(tmp_enc), str(MODEL_ACTIVE_DIR / "encoders.json"))
            copied.append("encoders.json")
        return jsonify({"active_dir": str(MODEL_ACTIVE_DIR),
                        "copied": copied,
                        "model_class": type(mdl).__name__})
    finally:
        try:
            for p in staging.iterdir():
                p.unlink()
            staging.rmdir()
        except OSError:
            pass


@app.get("/api/train/jobs")
def train_jobs() -> object:
    with _JOB_LOCK:
        items = sorted(_JOBS.values(), key=lambda j: j.get("updated_at", ""), reverse=True)
    return jsonify({"items": items[:100]})


@app.get("/api/train/job/<job_id>")
def train_job(job_id: str) -> object:
    j = _get_job(job_id)
    if not j:
        return jsonify({"error": "not found"}), 404
    return jsonify(j)


@app.get("/api/train/active-model")
def active_model() -> object:
    """Currently-active model files + mtime, so the UI can show 'last updated'."""
    info = {"dir": str(MODEL_ACTIVE_DIR), "files": []}
    if MODEL_ACTIVE_DIR.exists():
        for p in sorted(MODEL_ACTIVE_DIR.iterdir()):
            try:
                info["files"].append({
                    "name": p.name,
                    "size_bytes": p.stat().st_size,
                    "mtime": datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(),
                })
            except OSError:
                pass
    return jsonify(info)


# ── Health check ──────────────────────────────────────────────────────────
@app.get("/api/health")
def health() -> object:
    try:
        es.cluster.health(timeout="2s")
        return jsonify({"status": "ok", "es": ES_HOST}), 200
    except Exception as e:  # noqa: BLE001
        return jsonify({"status": "degraded", "error": str(e)}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=LISTEN_PORT)
