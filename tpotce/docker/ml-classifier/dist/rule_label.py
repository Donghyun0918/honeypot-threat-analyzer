"""Rule-based label fallback for documents the trained model cannot score.

Returns one of: Etc / Recon / Brute Force / Intrusion / Malware
"""
import re

WEB_ATTACK_RE = re.compile(
    r"(?i)("
    r"union\s+select|select\s+.+from|or\s+1\s*=\s*1|and\s+1\s*=\s*1"
    r"|<script|javascript:|onerror=|onload="
    r"|\.\./|\.\.\\|etc/passwd|/proc/"
    r"|cmd=|exec=|system\(|passthru\(|eval\("
    r"|wget\s|curl\s|nc\s|bash\s+-[ci]"
    r"|phpinfo\(\)|base64_decode"
    r")"
)

REVERSE_SHELL_KEYS = ("bash -i", "/dev/tcp", "nc -e", "mkfifo", "ncat")

# 원격에서 실행 파일을 끌어오는 전형적 패턴. 셸 명령이든 HTTP 페이로드든 같다.
_MALWARE_FETCH_RE = re.compile(
    r"(?i)(wget\s+https?://|curl\s+(-[a-zA-Z]+\s+)*https?://|tftp\s+-|"
    r"certutil\s+-urlcache|powershell\s+.*downloadstring)"
)

# 공격자가 보낸 텍스트가 담길 수 있는 필드. suricata 는 payload_printable 에
# 넣는데 예전에는 이 필드를 아무도 읽지 않아, 명령 근거가 통째로 버려졌다.
_TEXT_FIELDS = ("input", "command", "payload_printable", "payload", "message")


def _text_of(doc: dict) -> str:
    """공격자가 보낸 텍스트를 모은다(필드마다 흩어져 있다)."""
    parts = []
    for field in _TEXT_FIELDS:
        v = doc.get(field)
        if isinstance(v, list):
            v = " ".join(str(x) for x in v)
        if v is not None and str(v).strip() not in ("", "nan", "None"):
            parts.append(str(v))
    return " ".join(parts)


def _decisive_from_text(text: str) -> str | None:
    """내용만으로 확실히 판정되는 경우. 카테고리보다 우선한다.

    리버스셸이나 원격 실행파일 다운로드는 어떤 센서가 무슨 카테고리를 붙였든
    그 자체로 침입/악성코드다. suricata 는 이런 페이로드에도 종종
    ``attempted-recon`` 을 붙이는데, 그 라벨을 그대로 쓰면 학습 데이터가
    "리버스셸 = 정찰" 이라고 가르치게 된다.
    """
    if not text:
        return None
    low = text.lower()
    if any(k in low for k in REVERSE_SHELL_KEYS):
        return "Intrusion"
    if _MALWARE_FETCH_RE.search(text):
        return "Malware"
    return None

# Suricata alert categories that map to attack labels
_SURICATA_BRUTE = ("attempted-user", "unsuccessful-user", "policy-violation")
_SURICATA_MALWARE = ("trojan-activity", "malware", "targeted-activity", "exploit-kit")
# "network-scan" 은 정찰이다. 예전에는 INTRUSION 목록에도 들어 있었고 그쪽을
# 먼저 검사해서 스캔이 전부 침입으로 분류됐다(RECON 쪽 항목은 죽은 코드였다).
_SURICATA_INTRUSION = ("shellcode-detect", "successful-admin", "successful-user",
                       "attempted-admin", "web-application-attack")
_SURICATA_RECON = ("network-scan", "information-leak", "attempted-recon",
                   "successful-recon-numeric", "successful-recon-limited")


def _has(text: str, key: str) -> bool:
    return key in text.lower()


def _intval(d: dict, k: str) -> int:
    try:
        return int(d.get(k, 0) or 0)
    except (ValueError, TypeError):
        return 0


def _suricata_label(doc: dict) -> str:
    # 페이로드에 확실한 근거가 있으면 카테고리보다 그것을 믿는다.
    decisive = _decisive_from_text(_text_of(doc))
    if decisive:
        return decisive

    alert = doc.get("alert") or {}
    if isinstance(alert, str):
        return "Recon"

    category = str(alert.get("category") or "").strip()
    raw_severity = str(alert.get("severity") or "").strip()

    # Suricata 는 경보만이 아니라 flow·dns·tls 같은 자체 기록도 남긴다.
    # 그런 행에는 카테고리도 심각도도 없다 — 공격 근거가 아무것도 없다는 뜻이다.
    # (실측: 20만 행 중 146,441행 = 73%.) 이것을 Recon 으로 부르면 "정찰"의
    # 정의가 "센서가 뭔가 기록함"으로 무너지고, 학습셋이 그 라벨로 뒤덮인다.
    if not category and not raw_severity:
        return "Etc"

    category = category.lower()
    try:
        severity = int(float(raw_severity)) if raw_severity else 3
    except ValueError:
        severity = 3

    for cat in _SURICATA_MALWARE:
        if cat in category:
            return "Malware"
    for cat in _SURICATA_INTRUSION:
        if cat in category:
            return "Intrusion"
    for cat in _SURICATA_BRUTE:
        if cat in category:
            return "Brute Force"
    for cat in _SURICATA_RECON:
        if cat in category:
            return "Recon"
    # 카테고리로 못 가르면 심각도만 남는다. severity 2 를 Malware 로 보던
    # 예전 규칙은 근거가 없었다(멀웨어라는 신호가 어디에도 없다).
    if severity == 1:
        return "Intrusion"
    return "Recon"


def label_from_doc(doc: dict) -> str:
    """T-Pot ES document (logstash-*) → coarse attack label."""
    src_hp = str(doc.get("type") or doc.get("source_honeypot") or "").lower()
    proto = str(doc.get("protocol") or "").upper()
    ev_type = str(doc.get("eventid") or doc.get("event_type") or "").lower()
    cmd = _text_of(doc)

    # --- Suricata: use alert metadata ---
    if src_hp == "suricata":
        return _suricata_label(doc)

    # --- P0f: passive OS fingerprinting = Recon ---
    if src_hp == "p0f":
        return "Recon"

    # --- Fatt: TLS/network fingerprinting = Recon ---
    if src_hp == "fatt":
        return "Recon"

    # --- Dionaea: malware sample capture ---
    if src_hp == "dionaea":
        return "Malware"

    # --- ConPot / industrial honeypots = Recon ---
    if src_hp in ("conpot", "ipphoney", "dicompot", "medpot", "ciscoasa"):
        return "Recon"

    # --- Sentrypeer / Mailoney: VoIP/mail brute force ---
    if src_hp in ("sentrypeer", "mailoney"):
        return "Brute Force"

    # --- Cowrie: SSH/Telnet honeypot ---
    if "cowrie" in src_hp or src_hp == "cowrie":
        if any(_has(cmd, k) for k in REVERSE_SHELL_KEYS):
            return "Intrusion"
        if "command" in ev_type and (_has(cmd, "wget") or _has(cmd, "curl") or _has(cmd, "chmod")):
            return "Malware"
        if "login" in ev_type or "failed" in ev_type:
            return "Brute Force"
        return "Recon"

    # --- Heralding / H0neytr4p: credential harvesting ---
    if src_hp in ("heralding", "h0neytr4p"):
        return "Brute Force"

    # --- Honeytrap: generic TCP honeypot ---
    if src_hp == "honeytrap":
        decisive = _decisive_from_text(cmd)
        if decisive:
            return decisive
        if WEB_ATTACK_RE.search(cmd):
            return "Intrusion"
        return "Recon"

    # --- Snare/Tanner: web honeypot ---
    if src_hp in ("snare", "tanner"):
        decisive = _decisive_from_text(cmd)
        if decisive:
            return decisive
        if WEB_ATTACK_RE.search(cmd):
            return "Intrusion"
        return "Recon"

    # --- ElasticPot / Redishoneypot: DB honeypots ---
    if src_hp in ("elasticpot", "redishoneypot"):
        return "Intrusion"

    # --- NGINX: web server logs ---
    if src_hp == "nginx":
        if WEB_ATTACK_RE.search(cmd):
            return "Intrusion"
        return "Recon"

    # --- Generic fallbacks ---
    if any(_has(cmd, k) for k in REVERSE_SHELL_KEYS):
        return "Intrusion"
    if "command" in ev_type and (_has(cmd, "wget") or _has(cmd, "curl")):
        return "Malware"
    if "scan" in ev_type or proto == "PORTSCAN":
        return "Recon"
    if proto == "SMTP":
        return "Brute Force"
    if _intval(doc, "login_attempts") >= 3:
        return "Brute Force"
    if "login" in ev_type or "failed" in ev_type:
        return "Brute Force"

    return "Etc"


def is_attack(label: str) -> int:
    # "Normal" comes from NSL-KDD open dataset rows; treated same as Etc (benign)
    return 0 if label in ("Etc", "Normal") else 1
