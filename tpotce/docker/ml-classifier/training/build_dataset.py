"""Build a labeled training dataset from T-Pot's logstash-* indices.

Output schema (CSV with header):
    hour, is_night, day_of_week, dst_port, protocol, source_honeypot,
    event_type, login_success, duration, login_attempts, cmd_length,
    special_char_cnt, pipe_count, has_wget, has_curl, has_reverse_shell,
    label

Initial labels are produced by `rule_label.py` (weak supervision). The
trained model generalizes the rules with feature-space patterns and is
evaluated on a held-out test split (see train.py).

Usage:
    python build_dataset.py \\
        --es http://elasticsearch:9200 \\
        --since now-7d \\
        --max 50000 \\
        --out dataset.csv

홀드아웃을 뽑을 때는 **반드시 학습에 쓴 인코더를 넘긴다**:

    python build_dataset.py --since 2026-04-30 --out holdout.csv \\
        --encoders-in work/encoders.json

카테고리 코드는 그 호출이 본 문서에서 만들어지므로, 인코더를 새로 만들면
학습셋과 코드가 어긋난다. 2026-09-14 홀드아웃이 그랬다 — event_type 47종 중
22종이 밀려 20만 행 중 6만 행이 모델이 배운 적 없는 코드로 들어갔고,
그 결과 규칙 합의율이 99.9% 대신 92.5% 로 측정됐다.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter
from pathlib import Path

# Make the dist/ helpers importable from any of the locations they may live in:
#  - When run from the source tree:        ../dist/         (sibling of training/)
#  - When run inside threat-console image: /opt/ml-classifier/dist/
#  - Override:                             $ML_CLASSIFIER_DIST_PATH
HERE = Path(__file__).resolve().parent
for candidate in (
    os.getenv("ML_CLASSIFIER_DIST_PATH"),
    str(HERE.parent / "dist"),
    "/opt/ml-classifier/dist",
):
    if candidate and Path(candidate).is_dir():
        sys.path.insert(0, candidate)

import feature_extract  # noqa: E402
import rule_label       # noqa: E402

from elasticsearch import Elasticsearch, helpers  # noqa: E402


def _build_encoders(docs: list[dict]) -> dict:
    """Map categorical fields → integer codes (stable, sorted)."""
    cats = {"protocol": set(), "source_honeypot": set(), "event_type": set()}
    for d in docs:
        cats["protocol"].add(str(d.get("protocol") or ""))
        cats["source_honeypot"].add(str(d.get("type") or d.get("source_honeypot") or "").lower())
        cats["event_type"].add(str(d.get("eventid") or d.get("event_type") or ""))
    return {k: {v: i for i, v in enumerate(sorted(vs))} for k, vs in cats.items()}


def _encoder_coverage(docs: list[dict], encoders: dict) -> dict:
    """주어진 인코더가 문서를 얼마나 덮는지 — 미지 카테고리는 코드 0 이 된다.

    `feature_extract.extract` 는 모르는 값을 0 으로 떨어뜨리는데, 0 은 실제
    카테고리(정렬 첫 값)의 코드이기도 하다. 즉 커버리지가 낮으면 모델은
    엉뚱한 카테고리를 본 것과 같아진다. 조용히 넘어가면 안 되는 수치다.
    """
    seen = {"protocol": Counter(), "source_honeypot": Counter(), "event_type": Counter()}
    getters = {
        "protocol": lambda d: str(d.get("protocol") or ""),
        "source_honeypot": lambda d: str(d.get("type") or d.get("source_honeypot") or "").lower(),
        "event_type": lambda d: str(d.get("eventid") or d.get("event_type") or ""),
    }
    for d in docs:
        for field, get in getters.items():
            seen[field][get(d)] += 1
    report = {}
    for field, counts in seen.items():
        known = encoders.get(field, {})
        unknown = {v: n for v, n in counts.items() if v not in known}
        report[field] = {
            "values": len(counts),
            "unknown_values": sorted(unknown, key=lambda v: -unknown[v]),
            "unknown_rows": sum(unknown.values()),
        }
    return report


def fetch_docs(es: Elasticsearch, since: str, max_docs: int, source_index: str) -> list[dict]:
    body = {
        "size": 1000,
        "sort": [{"@timestamp": "asc"}, {"_seq_no": {"order": "asc", "unmapped_type": "long"}}],
        "query": {"range": {"@timestamp": {"gte": since}}},
    }
    docs = []
    cursor = None
    while len(docs) < max_docs:
        if cursor:
            body["search_after"] = cursor
        resp = es.search(index=source_index, body=body, ignore_unavailable=True)
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            break
        for h in hits:
            docs.append(h["_source"])
            if len(docs) >= max_docs:
                break
        cursor = hits[-1].get("sort")
    return docs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--es", default=os.getenv("ES_HOST", "http://127.0.0.1:64298"),
                    help="Elasticsearch URL (default: env ES_HOST or http://127.0.0.1:64298)")
    ap.add_argument("--source-index", default="logstash-*")
    ap.add_argument("--since", default="now-7d", help="ES date-math range start")
    ap.add_argument("--max", type=int, default=50000, help="max docs to pull")
    ap.add_argument("--out", default="dataset.csv", help="output CSV path")
    ap.add_argument("--encoders-out", default="encoders.json")
    ap.add_argument(
        "--encoders-in", default=None,
        help="기존 인코더 JSON 을 그대로 쓴다(새로 만들지 않는다). 학습셋과 "
             "같은 카테고리 코드를 써야 하는 홀드아웃·평가셋에는 필수다. "
             "넘긴 인코더는 --encoders-out 으로도 복사되어 CSV 와 함께 남는다.",
    )
    ap.add_argument(
        "--normal-csv", default=None,
        help="path to a CSV with Normal/Etc rows from an open dataset "
             "(fetch_normal.py downloads NSL-KDD normals automatically).",
    )
    ap.add_argument(
        "--balance-n", type=int, default=None,
        help="cap every class at this many samples, then randomly downsample "
             "majority classes. Minority classes are kept as-is (use --smote "
             "in train.py to upsample them). Recommended: 8000–10000 per class. "
             "Default: no balancing.",
    )
    ap.add_argument(
        "--from-csv", default=None,
        help="skip Elasticsearch and use a pre-built feature CSV as input "
             "(output of csv_to_training.py). Useful for local dev without ES.",
    )
    args = ap.parse_args()

    # ── Local CSV mode: skip ES entirely ─────────────────────────────────────
    if args.from_csv:
        import pandas as _pd
        print(f"Local CSV mode: loading {args.from_csv} …")
        df = _pd.read_csv(args.from_csv)
        header = feature_extract.FEATURE_COLS + ["label"]
        missing = [c for c in header if c not in df.columns]
        if missing:
            print(f"ERROR: input CSV missing columns: {missing}", file=sys.stderr)
            return 1
        rows = df[header].values.tolist()
        label_counts = Counter(str(r[-1]) for r in rows)
        print(f"Loaded {len(rows):,} rows from local CSV")
        print("Label distribution:")
        total = sum(label_counts.values()) or 1
        for k, v in label_counts.most_common():
            print(f"  {k:15s} {v:>8,}  ({v/total*100:5.1f}%)")
        # encoders-out: --encoders-in 이 있으면 그것, 없으면 입력 CSV 옆의 것
        enc_src = (Path(args.encoders_in) if args.encoders_in
                   else Path(args.from_csv).with_suffix("").parent / "encoders.json")
        if enc_src.exists() and not Path(args.encoders_out).exists():
            import shutil as _sh
            _sh.copy(str(enc_src), args.encoders_out)
            print(f"Copied encoders → {args.encoders_out}")
        # rows / label_counts already set above — skip to normal-csv section
    else:
        print(f"Connecting to {args.es} …")
        es = Elasticsearch(args.es, request_timeout=60)
        print(f"Pulling up to {args.max:,} docs from {args.source_index} since {args.since} …")
        docs = fetch_docs(es, args.since, args.max, args.source_index)
        print(f"Fetched {len(docs):,} documents")

        if not docs:
            print("No docs found — check --since or index pattern", file=sys.stderr)
            return 1

        if args.encoders_in:
            encoders = json.loads(Path(args.encoders_in).read_text(encoding="utf-8"))
            missing_keys = [k for k in ("protocol", "source_honeypot", "event_type")
                            if k not in encoders]
            if missing_keys:
                print(f"ERROR: --encoders-in 에 {missing_keys} 가 없다", file=sys.stderr)
                return 1
            print(f"Reusing encoders ← {args.encoders_in}  "
                  f"(proto={len(encoders['protocol'])}, "
                  f"hp={len(encoders['source_honeypot'])}, "
                  f"event={len(encoders['event_type'])})")
            cov = _encoder_coverage(docs, encoders)
            for field, r in cov.items():
                if r["unknown_rows"]:
                    pct = r["unknown_rows"] / len(docs) * 100
                    head = ", ".join(repr(v) for v in r["unknown_values"][:5])
                    more = "" if len(r["unknown_values"]) <= 5 else f" 외 {len(r['unknown_values']) - 5}종"
                    print(f"  WARNING: {field} 미지 카테고리 {len(r['unknown_values'])}종 "
                          f"→ {r['unknown_rows']:,}행 ({pct:.1f}%) 이 코드 0 으로 떨어진다: "
                          f"{head}{more}", file=sys.stderr)
        else:
            encoders = _build_encoders(docs)
            print(f"Built encoders from these docs  "
                  f"(proto={len(encoders['protocol'])}, "
                  f"hp={len(encoders['source_honeypot'])}, "
                  f"event={len(encoders['event_type'])})")
            print("  NOTE: 이 CSV 는 여기서 만든 코드 체계를 쓴다. 다른 인코더로 학습한 "
                  "모델을 이 CSV 로 평가하면 측정이 성립하지 않는다 — 평가셋이면 "
                  "--encoders-in 으로 학습 인코더를 넘길 것.", file=sys.stderr)
        Path(args.encoders_out).write_text(json.dumps(encoders, ensure_ascii=False, indent=2))
        print(f"Wrote encoders → {args.encoders_out}")

    if not args.from_csv:
        label_counts = Counter()
        rows = []
        for d in docs:
            feats = feature_extract.extract(d, encoders)
            label = rule_label.label_from_doc(d)
            rows.append(feats + [label])
            label_counts[label] += 1

    # ── Merge normal-traffic rows from open dataset ───────────────────────────
    if args.normal_csv:
        normal_path = Path(args.normal_csv)
        if not normal_path.exists():
            print(f"Warning: --normal-csv {args.normal_csv} not found, skipping",
                  file=sys.stderr)
        else:
            expected_cols = feature_extract.FEATURE_COLS + ["label"]
            normal_rows = []
            with open(normal_path, encoding="utf-8", newline="") as f:
                reader = csv.reader(f)
                file_header = next(reader, None)
                if file_header != expected_cols:
                    print(
                        f"Warning: normal-csv header mismatch\n"
                        f"  expected: {expected_cols}\n"
                        f"  got:      {file_header}",
                        file=sys.stderr,
                    )
                for row in reader:
                    normal_rows.append(row)
                    label_counts[row[-1]] += 1
            rows.extend(normal_rows)
            print(f"Merged {len(normal_rows):,} normal rows from {normal_path}")

    # ── Class balancing: downsample majority classes ──────────────────────────
    import random as _rnd
    if args.balance_n:
        target = args.balance_n
        print(f"\nBalancing: cap each class at {target:,} samples "
              "(downsample majority, keep minority as-is)")
        # Group rows by label
        by_label: dict = {}
        for row in rows:
            lbl = row[-1]
            by_label.setdefault(lbl, []).append(row)
        balanced = []
        label_counts.clear()
        for lbl, lbl_rows in sorted(by_label.items()):
            if len(lbl_rows) > target:
                kept = _rnd.sample(lbl_rows, target)
            else:
                kept = lbl_rows
            balanced.extend(kept)
            label_counts[lbl] = len(kept)
        _rnd.shuffle(balanced)   # mix classes so CSV isn't sorted by label
        rows = balanced
        print("After balancing:")
        for lbl, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
            print(f"  {lbl:15s}  {cnt:>8,}")

    header = feature_extract.FEATURE_COLS + ["label"]
    with open(args.out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)

    print(f"\nWrote {len(rows):,} rows → {args.out}")
    print("Label distribution:")
    total = sum(label_counts.values()) or 1
    for k, v in label_counts.most_common():
        print(f"  {k:15s} {v:>8,}  ({v/total*100:5.1f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
