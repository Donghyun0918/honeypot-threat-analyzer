"""Rebalance a weak-labelled honeypot dataset before training.

Why this exists
---------------
``rule_label.py`` assigns a label per honeypot, and for most honeypots that
label is a constant that ignores event content (``p0f -> Recon``,
``dionaea -> Malware``, ``sentrypeer -> Brute Force`` ...). The resulting
dataset therefore has two problems:

1. **Class shortcut.** 91% of the ``Brute Force`` rows come from a single
   honeypot (sentrypeer), so ``source_honeypot`` alone predicts the class and
   the model never has to look at behaviour.
2. **Within-honeypot burial.** cowrie is 98.8% ``Recon`` (session noise);
   its 582 ``Brute Force`` rows are drowned, so a trained model answers
   "Recon" for an obvious SSH brute force.

Naive per-class balancing (take N rows per label) fixes neither, because it
preserves the honeypot mix inside each class. This script caps each
**(label, honeypot) cell** first, which breaks the shortcut and lifts the
minority behaviours inside a honeypot, and only then trims each label to a
common size.

It cannot manufacture signal that the weak labels never had — see
``README.md`` for what this dataset can and cannot support.

Usage:
  python rebalance.py --csv work/dataset.csv --normal work/normal.csv \\
      --out work/balanced_v2.csv --cap-per-cell 2000 --cap-per-label 4000
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import random
import sys
from pathlib import Path


def _load(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _cell_key(row: dict) -> tuple:
    return (row.get("label", ""), row.get("source_honeypot", ""))


def _report(rows: list[dict], title: str, inv: dict | None = None) -> None:
    by_label = collections.Counter(r["label"] for r in rows)
    print(f"\n{title}  (총 {len(rows):,}행)")
    for label, n in by_label.most_common():
        hp = collections.Counter(
            r["source_honeypot"] for r in rows if r["label"] == label
        )
        top = ", ".join(
            f"{(inv.get(int(h), h) if inv else h)}:{c}" for h, c in hp.most_common(4)
        )
        share = 100.0 * hp.most_common(1)[0][1] / n if n else 0.0
        print(f"  {label:<12} {n:>7,}   최대 허니팟 비중 {share:5.1f}%   [{top}]")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="rule-labelled dataset (csv_to_training.py 출력)")
    ap.add_argument("--normal", help="추가 Normal 행 CSV (fetch_normal.py 출력)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--encoders", help="리포트에 허니팟 이름을 쓰기 위한 encoders.json")
    ap.add_argument("--cap-per-cell", type=int, default=2000,
                    help="(label, honeypot) 조합당 최대 행 수 — 지름길 차단")
    ap.add_argument("--cap-per-label", type=int, default=4000,
                    help="라벨당 최대 행 수 — 셀 상한 적용 후 트리밍")
    ap.add_argument("--signal-cols", default="has_reverse_shell,has_wget,has_curl",
                    help="이 컬럼 중 하나라도 1인 행은 상한을 적용해도 버리지 않는다")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    random.seed(args.seed)

    rows = _load(Path(args.csv))
    if args.normal:
        normal_rows = _load(Path(args.normal))
        for r in normal_rows:
            r.setdefault("label", "Normal")
        rows += normal_rows
        print(f"Normal {len(normal_rows):,}행 병합")

    inv = None
    if args.encoders:
        enc = json.loads(Path(args.encoders).read_text(encoding="utf-8"))
        inv = {v: k for k, v in enc.get("source_honeypot", {}).items()}

    _report(rows, "── 원본", inv)

    # 결정적 특징(리버스셸·원격 다운로드)을 가진 행은 전체의 0.4% 밖에 안 되는데,
    # 무작위 트리밍은 이것부터 지운다. 그러면 모델이 그 특징을 배울 표본이 사라진다.
    # 상한을 적용하되 이런 행은 먼저 확보하고 나머지를 채운다.
    signal_cols = [c.strip() for c in args.signal_cols.split(",") if c.strip()]

    def has_signal(r: dict) -> bool:
        return any(str(r.get(c, "0")).strip() not in ("", "0", "0.0") for c in signal_cols)

    # 1) (label, honeypot) 셀 상한
    cells: dict[tuple, list[dict]] = collections.defaultdict(list)
    for r in rows:
        cells[_cell_key(r)].append(r)

    capped: list[dict] = []
    for key, group in cells.items():
        if len(group) > args.cap_per_cell:
            keep = [r for r in group if has_signal(r)]
            rest = [r for r in group if not has_signal(r)]
            남은자리 = max(0, args.cap_per_cell - len(keep))
            group = keep + (random.sample(rest, 남은자리) if len(rest) > 남은자리 else rest)
        capped.extend(group)

    _report(capped, f"── 셀 상한 {args.cap_per_cell} 적용 후", inv)

    # 2) 라벨 상한 — 셀 비율을 유지하며 트리밍
    by_label: dict[str, list[dict]] = collections.defaultdict(list)
    for r in capped:
        by_label[r["label"]].append(r)

    final: list[dict] = []
    for label, group in by_label.items():
        if len(group) > args.cap_per_label:
            keep = [r for r in group if has_signal(r)]
            rest = [r for r in group if not has_signal(r)]
            남은자리 = max(0, args.cap_per_label - len(keep))
            group = keep + (random.sample(rest, 남은자리) if len(rest) > 남은자리 else rest)
        final.extend(group)

    random.shuffle(final)
    _report(final, f"── 라벨 상한 {args.cap_per_label} 적용 후 (최종)", inv)

    보존 = sum(1 for r in final if has_signal(r))
    print(f"\n결정적 특징 보유 행: 원본 {sum(1 for r in rows if has_signal(r)):,} → 최종 {보존:,} (전량 보존)")

    fieldnames = list(rows[0].keys())
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in final:
            w.writerow(r)
    print(f"\n{out} 에 {len(final):,}행 기록")
    return 0


if __name__ == "__main__":
    sys.exit(main())
