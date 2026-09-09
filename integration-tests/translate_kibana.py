"""Generate kibana_export_ko.ndjson from kibana_export.ndjson.

Conservative pass-1 translator:
  * Only the user-facing fields ``attributes.title``, ``attributes.description``,
    and ``attributes.name`` are touched.
  * Nested stringified JSON blobs (panelsJSON, visState, fieldAttrs,
    searchSourceJSON, …) are kept byte-for-byte identical so we don't
    accidentally break visualization layouts or query payloads.
  * Object IDs, references, types, version strings — untouched.

This is internal tooling — it lives outside tpot-fork/ so the PR diff is
just the generated ndjson, not the build script. Re-run after T-Pot
upstream updates kibana_export.ndjson.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Multi-word phrases are matched verbatim; single words are matched with
# Python regex word boundaries (``\b``) so e.g. "Attack" doesn't eat
# "Attacker". Always declare longer phrases first.
PHRASES: list[tuple[str, str]] = [
    ("Heralding Top Credentials Per Protocol", "Heralding 프로토콜별 상위 자격증명"),
    ("Suricata Events by Country Histogram",   "Suricata 국가별 이벤트 히스토그램"),
    ("Heatmap Destination Ports",              "목적지 포트 히트맵"),
    ("Attacks by Destination Ports Histogram", "목적지 포트별 공격 히스토그램"),
    ("Attacks by Country Histogram",           "국가별 공격 히스토그램"),
    ("Top Credentials Per Protocol",           "프로토콜별 상위 자격증명"),
    ("Attacker Src IP Reputation",             "공격자 출발지 IP 평판"),
    ("Attacker Number Relation",               "공격자 수 분석"),
    ("Country Protocol Relation",              "국가별 프로토콜 분포"),
    ("Attacks by Country",                     "국가별 공격"),
    ("Attacks by Port",                        "포트별 공격"),
    ("Events by Country",                      "국가별 이벤트"),
    ("Honeypot Statistics",                    "허니팟 통계"),
    ("Honeypot Names",                         "허니팟 이름"),
    ("Username Tagcloud",                      "사용자명 빈도"),
    ("Username Tag Cloud",                     "사용자명 빈도"),
    ("Password Tagcloud",                      "비밀번호 빈도"),
    ("Password Tag Cloud",                     "비밀번호 빈도"),
    ("Attacks Histogram",                      "공격 추이"),
    ("Attacks Bar",                            "공격 차트"),
    ("Attack Map",                             "공격 지도"),
    ("Attacker AS/N",                          "공격자 ASN"),
    ("Source Honeypot",                        "허니팟"),
    ("Source IP",                              "출발지 IP"),
    ("Src IP",                                 "출발지 IP"),
    ("Dest IP",                                "목적지 IP"),
    ("Dest Port",                              "목적지 포트"),
    ("Destination Ports",                      "목적지 포트"),
    ("Destination Port",                       "목적지 포트"),
    ("DestPort",                               "목적지 포트"),
    ("Top Downloads",                          "최다 다운로드"),
    ("Top 10",                                 "상위 10개"),
    ("Top 5",                                  "상위 5개"),
    ("Country Code",                           "국가 코드"),
    ("Request URI",                            "요청 URI"),
    ("User Agent",                             "사용자 에이전트"),
    ("HTTP Method",                            "HTTP 메서드"),
    ("Event Types",                            "이벤트 타입"),
    ("Event Type",                             "이벤트 타입"),
    ("Tag Cloud",                              "태그 클라우드"),
]

# Single English words. Order matters: longest stem first.
WORDS: list[tuple[str, str]] = [
    ("Attacker",    "공격자"),
    ("Attacks",     "공격"),
    ("Attack",      "공격"),
    ("Histogram",   "히스토그램"),
    ("Distribution","분포"),
    ("Heatmap",     "히트맵"),
    ("Countries",   "국가"),
    ("Country",     "국가"),
    ("Reputation",  "평판"),
    ("Protocols",   "프로토콜"),
    ("Protocol",    "프로토콜"),
    ("Username",    "사용자명"),
    ("Password",    "비밀번호"),
    ("Sessions",    "세션"),
    ("Session",     "세션"),
    ("Reason",      "사유"),
    ("Duration",    "지속시간"),
    ("Bytes",       "바이트"),
    ("Files",       "파일"),
    ("Downloads",   "다운로드"),
    ("Download",    "다운로드"),
    ("Identifier",  "식별자"),
    ("Levels",      "레벨"),
    ("Level",       "레벨"),
    ("Inputs",      "입력"),
    ("Input",       "입력"),
    ("Tagcloud",    "빈도"),
    ("Requests",    "요청"),
    ("Request",     "요청"),
    ("Source",      "출발지"),
    ("Destination", "목적지"),
    ("Dynamic",     "동적"),
    ("Statistics",  "통계"),
    ("Stats",       "통계"),
    ("Map",         "지도"),
    ("Bar",         "막대그래프"),
    ("Top",         "상위"),
    ("Pie",         "파이"),
    ("Version",     "버전"),
    ("Method",      "메서드"),
    ("Methods",     "메서드"),
    ("Logs",        "로그"),
    ("Events",      "이벤트"),
    ("Event",       "이벤트"),
    ("Directories", "디렉토리"),
    ("Directory",   "디렉토리"),
    ("Data",        "데이터"),
    ("Credentials", "자격증명"),
    ("Number",      "수"),
    ("Relation",    "관계"),
    ("Names",       "이름"),
    ("Name",        "이름"),
    ("Ports",       "포트"),
    ("Port",        "포트"),
    ("and",         "및"),

    # Common dashboard nouns
    ("Alerts",      "경보"),
    ("Alert",       "경보"),
    ("Honeypots",   "허니팟"),
    ("Honeypot",    "허니팟"),
    ("Hostname",    "호스트명"),
    ("Filenames",   "파일명"),
    ("Filename",    "파일명"),
    ("Fileinfo",    "파일정보"),
    ("Commands",    "명령어"),
    ("Detection",   "탐지"),
    ("Encoding",    "인코딩"),
    ("Signature",   "시그니처"),
    ("Software",    "소프트웨어"),
    ("Payload",     "페이로드"),
    ("Header",      "헤더"),
    ("Hash",        "해시"),
    ("Status",      "상태"),
    ("Response",    "응답"),
    ("Query",       "쿼리"),
    ("Packets",     "패킷"),
    ("Packet",      "패킷"),
    ("Output",      "출력"),
    ("Incoming",    "수신"),
    ("Language",    "언어"),
    ("Live",        "실시간"),
    ("Total",       "총합"),
    ("Upload",      "업로드"),
    ("Uploads",     "업로드"),
    ("Trapped",     "포획됨"),
    ("Trap",        "함정"),
    ("Body",        "본문"),
    ("Content",     "콘텐츠"),
    ("Category",    "카테고리"),
    ("Client",      "클라이언트"),
    ("Device",      "장비"),
    ("Path",        "경로"),
    ("Samples",     "샘플"),
    ("Sample",      "샘플"),
    ("Users",       "사용자"),
    ("Codes",       "코드"),
    ("Code",        "코드"),
    ("Type",        "타입"),
    ("Info",        "정보"),
    ("Unknown",     "알 수 없음"),
    ("Failed",      "실패"),
    ("Login",       "로그인"),
    ("Logins",      "로그인"),
    ("Attempts",    "시도"),
    ("Auth",        "인증"),
]

_WORD_PATTERNS = [(re.compile(r"\b" + re.escape(s) + r"\b"), d) for s, d in WORDS]


def translate(text: str) -> str:
    if not text:
        return text
    out = text
    for src, dst in PHRASES:
        out = out.replace(src, dst)
    for pat, dst in _WORD_PATTERNS:
        out = pat.sub(dst, out)
    return out


# Object types whose attributes hold the user-visible labels we want to localize.
TRANSLATABLE_TYPES = {
    "tag", "dashboard", "visualization", "search", "lens", "map",
    "index-pattern", "query",
}

TRANSLATABLE_FIELDS = ("title", "description", "name")


def transform_object(obj: dict) -> tuple[dict, int]:
    """Return (possibly mutated) object plus number of fields changed."""
    if obj.get("type") not in TRANSLATABLE_TYPES:
        return obj, 0

    attrs = obj.get("attributes")
    if not isinstance(attrs, dict):
        return obj, 0

    changed = 0
    for f in TRANSLATABLE_FIELDS:
        v = attrs.get(f)
        if isinstance(v, str) and v.strip():
            new_v = translate(v)
            if new_v != v:
                attrs[f] = new_v
                changed += 1
    return obj, changed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="/mnt/d/T-POT_PR/tpot-fork/docker/tpotinit/dist/etc/objects/kibana_export.ndjson")
    ap.add_argument("--dst", default="/mnt/d/T-POT_PR/tpot-fork/docker/tpotinit/dist/etc/objects/kibana_export_ko.ndjson")
    ap.add_argument("--report-sample", type=int, default=10,
                    help="show this many before/after pairs in the summary")
    args = ap.parse_args()

    src = Path(args.src)
    if not src.exists():
        print(f"source not found: {src}", file=sys.stderr)
        return 1

    out_lines: list[str] = []
    n_total = 0
    n_changed_objs = 0
    n_changed_fields = 0
    samples: list[tuple[str, str]] = []

    with src.open(encoding="utf-8") as f:
        for raw in f:
            stripped = raw.rstrip("\n")
            if not stripped.strip():
                out_lines.append(stripped)
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                # passthrough — never break the file even if the source has stray non-JSON
                out_lines.append(stripped)
                continue

            n_total += 1
            before_title = (obj.get("attributes") or {}).get("title") or \
                           (obj.get("attributes") or {}).get("name") or ""
            obj, changed = transform_object(obj)
            if changed:
                n_changed_objs += 1
                n_changed_fields += changed
                after_title = (obj.get("attributes") or {}).get("title") or \
                              (obj.get("attributes") or {}).get("name") or ""
                if before_title != after_title and len(samples) < args.report_sample:
                    samples.append((before_title, after_title))

            out_lines.append(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))

    # Match upstream: no trailing newline.
    Path(args.dst).write_text("\n".join(out_lines), encoding="utf-8")

    print(f"input  : {src}  ({n_total} objects)")
    print(f"output : {args.dst}")
    print(f"objects translated : {n_changed_objs}")
    print(f"fields  translated : {n_changed_fields}")
    print()
    print("=== sample translations ===")
    for b, a in samples:
        print(f"  {b}")
        print(f"    -> {a}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
