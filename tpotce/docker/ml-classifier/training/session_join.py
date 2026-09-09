"""Rebuild per-event feature completeness in honeypot CSV exports.

Why this exists
---------------
In live T-Pot, Logstash enriches every honeypot event so a single
``logstash-*`` document carries both the connection attributes (port,
protocol) and the behaviour (command, login outcome). The CSV exports in
``dataset/csv/`` do not: cowrie splits them across rows of the same session.

    cowrie.session.connect   41,725 rows   dst_port 23.0/22.0   no behaviour
    cowrie.login.failed       2,987 rows   dst_port EMPTY       the behaviour
    cowrie.command.input        125 rows   dst_port EMPTY       the behaviour

A model trained on those rows sees ``dst_port=0, login_attempts=0`` for the
very events it must classify, while at inference the same event arrives as
``dst_port=22, login_attempts=25`` — different regions of feature space.
See ``DATASET_FINDINGS.md`` §3.

This script closes that gap by doing on the CSV what Logstash does live:

1. **Propagate session attributes.** Fields that describe the connection
   (``dst_port``, ``protocol``, ``src_ip``, ``dst_ip``) are copied from the
   session's ``connect`` row onto every event row of that session.
2. **Derive ``login_attempts``.** Counted per session as the number of
   ``login.failed`` rows, then stamped on that session's login rows — the
   count a live document reports.
3. **Derive ``login_success``.** 1 on sessions that reached ``login.success``.
4. **Drop pure session bookkeeping.** ``session.connect`` / ``session.closed``
   rows carry no behaviour and are 89.9% of cowrie; keeping them buries every
   real event under noise. They are dropped *after* their attributes have been
   harvested, so nothing is lost.

Output is one enriched CSV per input, written to ``--out-dir``, ready for
``csv_to_training.py``. Files without a usable session key are copied
unchanged so the directory stays a drop-in replacement.

Usage:
  python session_join.py --csv-dir dataset/csv --out-dir dataset/csv_joined
"""
from __future__ import annotations

import argparse
import collections
import csv
import shutil
import sys
from pathlib import Path

# Attributes that belong to the connection, not the individual event, and so
# may be carried across rows sharing a session id.
SESSION_ATTRS = ("dst_port", "dest_port", "protocol", "src_ip", "dst_ip", "src_port")

# Rows that exist only to open/close a session. Dropped after harvesting.
BOOKKEEPING = {
    "cowrie.session.connect",
    "cowrie.session.closed",
    "cowrie.log.closed",
    "cowrie.client.version",
    "cowrie.client.kex",
    "cowrie.client.size",
    "cowrie.client.var",
    "cowrie.session.params",
}

FAILED_EVENTS = {"cowrie.login.failed"}
SUCCESS_EVENTS = {"cowrie.login.success"}


def _blank(v) -> bool:
    return v is None or str(v).strip() in ("", "nan", "NaN", "None")


def _event_of(row: dict) -> str:
    return str(row.get("eventid") or row.get("event_type") or "").strip()


def enrich(rows: list[dict], keep_bookkeeping: bool) -> tuple[list[dict], dict]:
    """Propagate session attributes and derive login counters."""
    sessions: dict[str, list[dict]] = collections.defaultdict(list)
    for r in rows:
        sid = str(r.get("session") or "").strip()
        if sid:
            sessions[sid].append(r)

    stats = collections.Counter()

    for sid, group in sessions.items():
        # 1) harvest connection attributes from any row in the session that has them
        harvested: dict[str, str] = {}
        for attr in SESSION_ATTRS:
            for r in group:
                v = r.get(attr)
                if not _blank(v):
                    harvested[attr] = v
                    break

        # 2) count login outcomes across the session
        failed = sum(1 for r in group if _event_of(r) in FAILED_EVENTS)
        success = 1 if any(_event_of(r) in SUCCESS_EVENTS for r in group) else 0

        for r in group:
            for attr, v in harvested.items():
                if _blank(r.get(attr)):
                    r[attr] = v
                    stats["filled_" + attr] += 1
            ev = _event_of(r)
            if ev in FAILED_EVENTS or ev in SUCCESS_EVENTS:
                if failed:
                    r["login_attempts"] = failed
                    stats["login_attempts"] += 1
                r["login_success"] = success

    if keep_bookkeeping:
        return rows, stats

    kept = [r for r in rows if _event_of(r) not in BOOKKEEPING]
    stats["dropped_bookkeeping"] = len(rows) - len(kept)
    return kept, stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--keep-bookkeeping", action="store_true",
                    help="session connect/closed 행을 남긴다 (기본: 제거)")
    args = ap.parse_args()

    src = Path(args.csv_dir)
    dst = Path(args.out_dir)
    dst.mkdir(parents=True, exist_ok=True)

    for path in sorted(src.glob("*.csv")):
        with path.open(encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            fields = list(reader.fieldnames or [])
            rows = list(reader)

        if "session" not in fields or not rows:
            shutil.copy2(path, dst / path.name)
            print(f"  {path.name:<20} {len(rows):>8,}행  (session 없음 → 복사)")
            continue

        for extra in ("login_attempts", "login_success"):
            if extra not in fields:
                fields.append(extra)

        enriched, stats = enrich(rows, args.keep_bookkeeping)

        with (dst / path.name).open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(enriched)

        detail = ", ".join(
            f"{k}={v:,}" for k, v in sorted(stats.items()) if v
        ) or "변경 없음"
        print(f"  {path.name:<20} {len(rows):>8,} → {len(enriched):>7,}행  {detail}")

    print(f"\n{dst} 에 기록 완료")
    return 0


if __name__ == "__main__":
    sys.exit(main())
