"""Convert raw honeypot CSV logs (from convert_logs.py) to ML training format.

Instead of querying Elasticsearch, reads the already-downloaded CSV files
and produces the same 16-feature + label dataset that build_dataset.py emits.

Usage (quickstart — no Elasticsearch needed):
    # 1. Convert raw CSVs to training format
    python csv_to_training.py \\
        --csv-dir /mnt/d/T-POT_PR/logs/csv \\
        --out dataset.csv \\
        --encoders-out encoders.json

    # 2. Fetch NSL-KDD normal traffic
    python fetch_normal.py --n 10000 --out normal.csv --encoders encoders.json

    # 3. Merge normal + balance
    python build_dataset.py \\
        --from-csv dataset.csv \\
        --normal-csv normal.csv \\
        --balance-n 10000 \\
        --out balanced.csv \\
        --encoders-out encoders.json

    # 4. Train
    python train.py --csv balanced.csv --encoders encoders.json --out-dir models/

Or use the threat-console UI:
    ML 학습 탭 → CSV 업로드 → balanced.csv 업로드 → 학습 시작
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _cand in (
    os.getenv("ML_CLASSIFIER_DIST_PATH"),
    str(HERE.parent / "dist"),
    "/opt/ml-classifier/dist",
):
    if _cand and Path(_cand).is_dir():
        sys.path.insert(0, _cand)
        break

import feature_extract  # noqa: E402
import rule_label       # noqa: E402

# Map CSV filename stem → T-Pot honeypot type string
# (used by rule_label.label_from_doc via doc["type"])
_HP_TYPE = {
    "cowrie":        "cowrie",
    "dionaea":       "dionaea",
    "suricata":      "suricata",
    "heralding":     "heralding",
    "sentrypeer":    "sentrypeer",
    "honeytrap":     "honeytrap",
    "conpot":        "conpot",
    "elasticpot":    "elasticpot",
    "redishoneypot": "redishoneypot",
    "adbhoney":      "adbhoney",
    "fatt":          "fatt",
    "p0f":           "p0f",
    "mailoney":      "mailoney",
    "miniprint":     "miniprint",
    "h0neytr4p":     "h0neytr4p",
    "honeyaml":      "honeyaml",
    "ipphoney":      "ipphoney",
    "tanner":        "tanner",
    "ciscoasa":      "ciscoasa",
}


def _clean(v):
    """NaN / empty → None."""
    if v is None:
        return None
    if isinstance(v, float) and math.isnan(v):
        return None
    if isinstance(v, str) and v.strip() in ("", "nan", "NaN", "None"):
        return None
    return v


def _row_to_doc(row: dict, hp_type: str) -> dict:
    doc = {k: _clean(v) for k, v in row.items()}
    doc["type"] = hp_type
    # suricata: rebuild nested alert{} from flattened alert.* columns
    if hp_type == "suricata":
        alert = {k[6:]: v for k, v in doc.items()
                 if k.startswith("alert.") and _clean(v) is not None}
        if alert:
            doc["alert"] = alert
    return doc


def _build_encoders_from_docs(docs: list[dict]) -> dict:
    cats: dict = {"protocol": set(), "source_honeypot": set(), "event_type": set()}
    for d in docs:
        cats["protocol"].add(str(d.get("protocol") or ""))
        cats["source_honeypot"].add(
            str(d.get("type") or d.get("source_honeypot") or "").lower()
        )
        cats["event_type"].add(str(d.get("eventid") or d.get("event_type") or ""))
    return {k: {v: i for i, v in enumerate(sorted(vs))} for k, vs in cats.items()}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Convert raw honeypot CSV logs to ML training format "
                    "(16 features + label). No Elasticsearch required."
    )
    ap.add_argument(
        "--csv-dir", required=True,
        help="directory containing per-honeypot CSVs (output of convert_logs.py)",
    )
    ap.add_argument("--out",          default="dataset.csv")
    ap.add_argument("--encoders-out", default="encoders.json")
    ap.add_argument(
        "--max-per-hp", type=int, default=50000,
        help="max rows to read per honeypot CSV (default: 50000)",
    )
    ap.add_argument(
        "--honeypots", default=None,
        help="comma-separated list of honeypots to include "
             "(default: all found in --csv-dir)",
    )
    args = ap.parse_args()

    csv_dir = Path(args.csv_dir)
    if not csv_dir.is_dir():
        print(f"ERROR: {args.csv_dir} is not a directory", file=sys.stderr)
        return 1

    filter_hps = set(args.honeypots.split(",")) if args.honeypots else None

    # ── Pass 1: collect all docs to build encoders ────────────────────────────
    print("Pass 1: scanning for encoder vocabulary…")
    all_docs: list[dict] = []
    for csv_path in sorted(csv_dir.glob("*.csv")):
        hp = csv_path.stem
        if hp not in _HP_TYPE:
            continue
        if filter_hps and hp not in filter_hps:
            continue
        try:
            import pandas as _pd
            df = _pd.read_csv(csv_path, low_memory=False, nrows=args.max_per_hp)
        except Exception as e:
            print(f"  skip {hp}: {e}")
            continue
        for _, row in df.iterrows():
            all_docs.append(_row_to_doc(row.to_dict(), _HP_TYPE[hp]))
        print(f"  {hp}: {len(df):,} rows loaded")

    if not all_docs:
        print("ERROR: no docs loaded — check --csv-dir path", file=sys.stderr)
        return 1

    encoders = _build_encoders_from_docs(all_docs)
    Path(args.encoders_out).write_text(
        json.dumps(encoders, ensure_ascii=False, indent=2)
    )
    print(f"Encoders saved → {args.encoders_out}")

    # ── Pass 2: extract features + label ─────────────────────────────────────
    print("\nPass 2: extracting features and applying rule labels…")
    label_counts: Counter = Counter()
    rows_out: list[list] = []

    for doc in all_docs:
        try:
            feats = feature_extract.extract(doc, encoders)
            label = rule_label.label_from_doc(doc)
        except Exception:
            continue
        rows_out.append(feats + [label])
        label_counts[label] += 1

    header = feature_extract.FEATURE_COLS + ["label"]
    with open(args.out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows_out)

    print(f"\nWrote {len(rows_out):,} rows → {args.out}")
    print("Label distribution:")
    total = sum(label_counts.values()) or 1
    for lbl, cnt in label_counts.most_common():
        bar = "█" * int(cnt / total * 30)
        print(f"  {lbl:15s}  {cnt:>8,}  ({cnt/total*100:5.1f}%)  {bar}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
