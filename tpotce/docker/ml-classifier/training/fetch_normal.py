"""Download NSL-KDD and extract 'normal' class rows mapped to T-Pot's 16-feature schema.

NSL-KDD (2009, UNB) is the standard IDS benchmark with a genuine 'normal' class
representing legitimate network traffic. Using real labelled normals is more reliable
than synthetic generation.

Reference: Tavallaee et al., "A detailed analysis of the KDD CUP 99 data set", 2009.
GitHub mirror: https://github.com/defcom17/NSL_KDD

Feature mapping (NSL-KDD 41 cols → our 16)
-------------------------------------------
hour / is_night / day_of_week  — NSL-KDD has no timestamps; sampled uniformly
dst_port                       — mapped from 'service' name to well-known port
protocol                       — protocol_type (tcp/udp/icmp) → encoders int
source_honeypot                — 0  (not from a honeypot)
event_type                     — 0
login_success                  — logged_in column
duration                       — duration column (seconds)
login_attempts                 — num_failed_logins
cmd_length / special_char_cnt / pipe_count / has_wget / has_curl / has_reverse_shell
                               — all 0 for benign traffic (no shell commands)

Usage
-----
    python fetch_normal.py --n 10000 --out normal.csv
    python fetch_normal.py --n 10000 --out normal.csv --encoders encoders.json
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import urllib.request
from pathlib import Path

# Allow running from training/ without installing the package
HERE = Path(__file__).resolve().parent
import os
for _cand in (
    os.getenv("ML_CLASSIFIER_DIST_PATH"),
    str(HERE.parent / "dist"),
    "/opt/ml-classifier/dist",
):
    if _cand and Path(_cand).is_dir():
        sys.path.insert(0, _cand)
        break

from feature_extract import FEATURE_COLS  # noqa: E402

# NSL-KDD public mirror (GitHub, MIT-style open access)
_KDDTRAIN_URL = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
)

# NSL-KDD column order (41 features + class + difficulty)
_KDD_COLS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "class", "difficulty",
]

# NSL-KDD service name → common port number
_SERVICE_PORT = {
    "http": 80, "https": 443, "ftp": 21, "ftp_data": 20,
    "smtp": 25, "ssh": 22, "telnet": 23, "domain": 53,
    "pop3": 110, "imap4": 143, "finger": 79, "whois": 43,
    "mtp": 57, "bgp": 179, "ldap": 389, "klogin": 543,
    "kshell": 544, "sql_net": 1521, "printer": 515,
    "nntp": 119, "ntp_u": 123, "time": 37, "echo": 7,
    "discard": 9, "daytime": 13, "chargen": 19, "netstat": 15,
    "systat": 11, "uucp": 540, "Z39_50": 210, "gopher": 70,
    "IRC": 194, "urp_i": 0, "red_i": 0, "eco_i": 0,
    "private": 1024, "other": 0,
}

# NSL-KDD protocol_type string → int encoding (will be overridden by encoders.json if present)
_PROTO_DEFAULT = {"tcp": 1, "udp": 2, "icmp": 3}


def _download_kdd(cache_path: Path) -> Path:
    if cache_path.exists():
        print(f"Using cached NSL-KDD: {cache_path}")
        return cache_path
    print(f"Downloading NSL-KDD from {_KDDTRAIN_URL} …")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(_KDDTRAIN_URL, str(cache_path))
    print(f"Saved → {cache_path}")
    return cache_path


def _parse_kdd_normal(kdd_path: Path) -> list[dict]:
    """Return all rows where class == 'normal'."""
    rows = []
    with open(kdd_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) < len(_KDD_COLS):
                continue
            rec = dict(zip(_KDD_COLS, parts))
            if rec.get("class", "").strip().lower() == "normal":
                rows.append(rec)
    return rows


def _to_feature_row(rec: dict, encoders: dict, rng: random.Random) -> list:
    """Map one NSL-KDD normal record to our 16-feature vector."""
    # Time features: NSL-KDD has no timestamps → uniform random
    hour     = rng.randint(0, 23)
    is_night = 1 if hour >= 22 or hour < 6 else 0
    dow      = rng.randint(0, 6)

    # Network
    service     = rec.get("service", "other").strip()
    dst_port    = _SERVICE_PORT.get(service, 0)
    proto_str   = rec.get("protocol_type", "tcp").strip().lower()
    proto_enc   = encoders.get("protocol", _PROTO_DEFAULT)
    protocol    = proto_enc.get(proto_str, 0)

    # Honeypot-specific (not applicable for normal traffic)
    src_hp     = encoders.get("source_honeypot", {}).get("", 0)
    event_type = encoders.get("event_type", {}).get("", 0)

    # Auth / session
    try:
        login_success  = int(rec.get("logged_in", "0"))
    except ValueError:
        login_success  = 0
    try:
        duration       = float(rec.get("duration", "0"))
    except ValueError:
        duration       = 0.0
    try:
        login_attempts = int(rec.get("num_failed_logins", "0"))
    except ValueError:
        login_attempts = 0

    # Command features — always 0 for benign traffic
    cmd_length    = 0
    special_chars = 0
    pipe_count    = 0
    has_wget      = 0
    has_curl      = 0
    has_revshell  = 0

    return [
        hour, is_night, dow,
        dst_port, protocol, src_hp, event_type,
        login_success, duration, login_attempts,
        cmd_length, special_chars, pipe_count,
        has_wget, has_curl, has_revshell,
    ]


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Fetch NSL-KDD normal traffic and convert to T-Pot 16-feature CSV"
    )
    ap.add_argument("--n",        type=int, default=10000,
                    help="number of normal rows to emit (default: 10000)")
    ap.add_argument("--out",      default="normal.csv",
                    help="output CSV path (default: normal.csv)")
    ap.add_argument("--encoders", default=None,
                    help="encoders.json from build_dataset.py — ensures protocol "
                         "encoding matches the attack dataset")
    ap.add_argument("--cache",    default=None,
                    help="local path to cache the raw KDDTrain+.txt "
                         "(default: same dir as --out)")
    ap.add_argument("--seed",     type=int, default=42)
    args = ap.parse_args()

    encoders: dict = {}
    if args.encoders:
        p = Path(args.encoders)
        if p.exists():
            encoders = json.loads(p.read_text(encoding="utf-8"))
            print(f"Loaded encoders: {args.encoders}")

    out_path   = Path(args.out)
    cache_path = Path(args.cache) if args.cache else out_path.parent / "KDDTrain+.txt"
    kdd_path   = _download_kdd(cache_path)

    print("Parsing NSL-KDD normal rows…")
    normal_recs = _parse_kdd_normal(kdd_path)
    print(f"Found {len(normal_recs):,} normal records in NSL-KDD")

    if not normal_recs:
        print("ERROR: no normal records found", file=sys.stderr)
        return 1

    rng = random.Random(args.seed)
    # Sample (with replacement if requested n > available)
    if args.n <= len(normal_recs):
        selected = rng.sample(normal_recs, args.n)
    else:
        # Repeat with slight jitter via re-sampling
        selected = rng.choices(normal_recs, k=args.n)
        print(f"NOTE: requested {args.n:,} > available {len(normal_recs):,} — "
              "sampling with replacement")

    header = FEATURE_COLS + ["label"]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for rec in selected:
            row = _to_feature_row(rec, encoders, rng)
            w.writerow(row + ["Normal"])

    print(f"Wrote {len(selected):,} normal rows → {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
