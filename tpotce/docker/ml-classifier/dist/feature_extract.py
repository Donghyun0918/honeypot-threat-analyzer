"""T-Pot Elasticsearch document → ML feature vector.

Mirrors the 16 features used by honeypot-integrated/backend/ml_service.py
but reads them straight from a logstash-* doc, not the legacy CSV pipeline.
"""
import re
from datetime import datetime, timezone

FEATURE_COLS = [
    "hour", "is_night", "day_of_week",
    "dst_port", "protocol", "source_honeypot", "event_type",
    "login_success", "duration", "login_attempts",
    "cmd_length", "special_char_cnt", "pipe_count",
    "has_wget", "has_curl", "has_reverse_shell",
]

_SPECIAL_RE = re.compile(r"[|;&><$`\\]")


def _parse_ts(s):
    if not s:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def _intval(v) -> int:
    # Go through float first: CSV exports carry numeric columns as "23.0",
    # and int("23.0") raises, which silently turned every port and count in
    # the CSV training path into 0 while live ES docs (ints) came through
    # fine — the two paths disagreed on the same event.
    try:
        return int(float(v or 0))
    except (ValueError, TypeError):
        return 0


def _floatval(v) -> float:
    try:
        return float(v or 0.0)
    except (ValueError, TypeError):
        return 0.0


# Fields that can carry attacker-supplied text, in priority order. Suricata
# puts it in payload_printable rather than input/command/message; skipping
# those fields cost the command features their only substantial source —
# cowrie contributes 10 wget rows and 0 reverse-shell rows, while suricata
# payloads hold 891 and 443 respectively.
_COMMAND_FIELDS = (
    "input", "command", "payload_printable", "payload", "message",
)


def _command_text(doc: dict) -> str:
    for field in _COMMAND_FIELDS:
        cmd = doc.get(field)
        if isinstance(cmd, list):
            cmd = " ".join(str(x) for x in cmd)
        if cmd is not None and str(cmd).strip() not in ("", "nan", "None"):
            return str(cmd)
    return ""


def extract(doc: dict, encoders: dict | None = None) -> list:
    """Return feature vector in FEATURE_COLS order."""
    enc = encoders or {}

    dt = _parse_ts(doc.get("@timestamp") or doc.get("timestamp"))
    hour = dt.hour
    is_night = 1 if hour >= 22 or hour < 6 else 0
    dow = dt.weekday()

    dst_port = _intval(doc.get("dest_port") or doc.get("dst_port"))
    proto_str = str(doc.get("protocol") or "")
    hp_str = str(doc.get("type") or doc.get("source_honeypot") or "").lower()
    event_str = str(doc.get("eventid") or doc.get("event_type") or "")

    protocol = enc.get("protocol", {}).get(proto_str, 0)
    source_honeypot = enc.get("source_honeypot", {}).get(hp_str, 0)
    event_type = enc.get("event_type", {}).get(event_str, 0)

    login_success = _intval(doc.get("login_success"))
    duration = _floatval(doc.get("duration"))
    login_attempts = _intval(doc.get("login_attempts"))

    cmd = _command_text(doc)
    cmd_length = len(cmd)
    special_char_cnt = len(_SPECIAL_RE.findall(cmd))
    pipe_count = cmd.count("|")
    cmd_low = cmd.lower()
    has_wget = int("wget" in cmd_low)
    has_curl = int("curl" in cmd_low)
    has_revshell = int(any(k in cmd_low for k in (
        "bash -i", "/dev/tcp", "nc -e", "mkfifo", "ncat",
    )))

    return [
        hour, is_night, dow,
        dst_port, protocol, source_honeypot, event_type,
        login_success, duration, login_attempts,
        cmd_length, special_char_cnt, pipe_count,
        has_wget, has_curl, has_revshell,
    ]
