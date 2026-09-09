"""Synthetic normal-traffic generator for T-Pot ML training.

Generates a CSV of realistic "Etc" (benign) samples to address the
honeypot coverage gap: honeypots see only attack traffic, so without
synthetic normals the model has no negative class to anchor on.

Design choices
--------------
* All attack-indicator features (has_wget, has_curl, has_reverse_shell,
  special_char_cnt, pipe_count, cmd_length) are 0 for normal traffic.
* dst_port follows the real-world service distribution (HTTP/HTTPS dominant).
* login_attempts is 1 with occasional 0 (no auth interaction).
* login_success follows a realistic success rate (~70%).
* Timestamps are drawn uniformly across 24h/7d to avoid hour-of-day bias.

Usage
-----
    python generate_normal.py --n 5000 --out normal.csv
    python generate_normal.py --n 5000 --out normal.csv --encoders encoders.json

The resulting CSV uses the same 16-column + label schema as build_dataset.py.
Pass it to build_dataset.py via --normal-csv, or directly to train.py via
--train-csv after merging with the attack dataset.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

from feature_extract import FEATURE_COLS  # noqa: E402 — same package


# Realistic dst_port distribution (weight = relative frequency)
_PORT_WEIGHTS = {
    80:    30,   # HTTP
    443:   35,   # HTTPS
    22:     8,   # SSH (legitimate admin)
    53:    10,   # DNS
    25:     3,   # SMTP
    110:    2,   # POP3
    143:    2,   # IMAP
    3306:   3,   # MySQL
    5432:   2,   # PostgreSQL
    8080:   3,   # HTTP alt
    8443:   1,   # HTTPS alt
    21:     1,   # FTP
}
_PORTS   = list(_PORT_WEIGHTS.keys())
_WEIGHTS = list(_PORT_WEIGHTS.values())


def _weighted_port() -> int:
    return random.choices(_PORTS, weights=_WEIGHTS, k=1)[0]


def _encode(value: str, mapping: dict) -> int:
    return mapping.get(value, 0)


def generate_row(encoders: dict, rng: random.Random) -> list:
    hour        = rng.randint(0, 23)
    is_night    = 1 if hour >= 22 or hour < 6 else 0
    dow         = rng.randint(0, 6)
    dst_port    = rng.choices(_PORTS, weights=_WEIGHTS, k=1)[0]
    protocol    = _encode("tcp", encoders.get("protocol", {}))
    src_hp      = _encode("", encoders.get("source_honeypot", {}))   # no honeypot
    event_type  = _encode("", encoders.get("event_type", {}))        # no event

    # Normal traffic: no attack commands, low login activity
    login_success  = rng.choices([0, 1], weights=[30, 70], k=1)[0]
    duration       = round(rng.uniform(0.01, 5.0), 3)
    login_attempts = rng.choices([0, 1, 2], weights=[40, 50, 10], k=1)[0]
    cmd_length     = 0
    special_char   = 0
    pipe_count     = 0
    has_wget       = 0
    has_curl       = 0
    has_revshell   = 0

    return [
        hour, is_night, dow,
        dst_port, protocol, src_hp, event_type,
        login_success, duration, login_attempts,
        cmd_length, special_char, pipe_count,
        has_wget, has_curl, has_revshell,
        "Etc",
    ]


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate synthetic normal-traffic samples (label=Etc)"
    )
    ap.add_argument("--n",        type=int, default=5000,
                    help="number of normal samples to generate (default: 5000)")
    ap.add_argument("--out",      default="normal.csv",
                    help="output CSV path (default: normal.csv)")
    ap.add_argument("--encoders", default=None,
                    help="encoders.json produced by build_dataset.py — "
                         "use the same encoding as your attack dataset")
    ap.add_argument("--seed",     type=int, default=42,
                    help="random seed for reproducibility (default: 42)")
    args = ap.parse_args()

    encoders: dict = {}
    if args.encoders:
        p = Path(args.encoders)
        if p.exists():
            encoders = json.loads(p.read_text(encoding="utf-8"))
            print(f"Loaded encoders from {p}")
        else:
            print(f"Warning: {args.encoders} not found — using empty encoders")

    rng = random.Random(args.seed)
    header = FEATURE_COLS + ["label"]
    rows = [generate_row(encoders, rng) for _ in range(args.n)]

    with open(args.out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)

    print(f"Wrote {args.n:,} normal-traffic rows → {args.out}")
    return 0


if __name__ == "__main__":
    import sys
    # Allow running from training/ dir without installing the package
    import os
    HERE = Path(__file__).resolve().parent
    for candidate in (
        os.getenv("ML_CLASSIFIER_DIST_PATH"),
        str(HERE.parent / "dist"),
        "/opt/ml-classifier/dist",
    ):
        if candidate and Path(candidate).is_dir():
            sys.path.insert(0, candidate)
            break
    sys.exit(main())
