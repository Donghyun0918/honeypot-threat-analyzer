"""Korean prompt + response parsing for llm-analyzer.

The model is asked for a strict JSON object. Every consumer of
``llm-analysis-*`` (threat-console, the Spring backend, the Next.js UI)
reads the same five fields, so parsing is defensive: a malformed or partial
response degrades to a deterministic fallback rather than dropping the
document.
"""
from __future__ import annotations

import json
import re

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# Honeypot name -> short Korean description, to give the model context it
# cannot infer from the index name alone.
_HONEYPOT_KO = {
    "cowrie": "SSH/Telnet 셸 허니팟",
    "dionaea": "멀웨어 수집 허니팟 (SMB/FTP/MSSQL 등)",
    "suricata": "네트워크 침입 탐지 센서",
    "p0f": "패시브 OS 핑거프린팅 센서",
    "honeytrap": "범용 TCP 포트 허니팟",
    "heralding": "인증 자격증명 수집 허니팟",
    "tanner": "웹 애플리케이션 허니팟 (SNARE 연동)",
    "adbhoney": "Android Debug Bridge 허니팟",
    "elasticpot": "Elasticsearch 허니팟",
    "mailoney": "SMTP 허니팟",
    "conpot": "산업제어시스템(ICS/SCADA) 허니팟",
    "redishoneypot": "Redis 허니팟",
    "wordpot": "WordPress 허니팟",
    "ipphoney": "IPP 프린터 허니팟",
    "medpot": "의료정보(HL7/FHIR) 허니팟",
}


def _fmt(value, fallback: str = "알 수 없음") -> str:
    if value is None or value == "":
        return fallback
    return str(value)


def build_prompt(doc: dict, ask_severity: bool = False) -> str:
    """Render the Korean analysis prompt for one ml-analysis document.

    ``ask_severity`` decides whether the model is asked to judge severity at
    all. Measured on the shipped model (qwen2.5:3b, 10 high-risk documents):
    it placed severity *below* the score-derived floor 10/10 times, and adding
    worked examples to the prompt changed nothing — 10/10 again. That is a
    capability limit, not a prompt defect, so by default severity is derived
    from ``mitre_score`` and the model is asked only for prose it does well.
    Set ``LLM_SEVERITY=model`` to hand the judgement back to a stronger model.
    """
    honeypot = _fmt(doc.get("honeypot"))
    honeypot_desc = _HONEYPOT_KO.get(str(doc.get("honeypot") or "").lower(), "허니팟")
    technique = doc.get("mitre_technique")
    technique_s = ", ".join(technique) if isinstance(technique, list) else _fmt(technique, "미분류")

    if ask_severity:
        severity_rule = (
            '3. "severity" — LOW, MEDIUM, HIGH, CRITICAL 중 하나.\n'
            "   **이 이벤트는 이미 고위험으로 선별되어 전달된 것입니다.**\n"
            "   MITRE 위협 점수 기준을 반드시 지키십시오: 90점 이상은 CRITICAL,\n"
            "   70점 이상은 HIGH, 40점 이상은 MEDIUM. 이보다 낮게 매기지 마십시오.\n"
            '4. "risk_score" — 0에서 10 사이의 숫자. severity와 모순되지 않게.\n'
        )
        severity_json = '\n  "severity": "LOW|MEDIUM|HIGH|CRITICAL",\n  "risk_score": 0,'
        # renumber the trailing instruction
        tail_no = "5"
    else:
        severity_rule = ""
        severity_json = ""
        tail_no = "3"

    return f"""당신은 한국어로 보고하는 침해대응(CERT) 분석가입니다.
아래는 허니팟에서 수집되어 1차 ML 분류를 마친 공격 이벤트입니다.
이를 2차 분석하여 지정된 JSON 형식으로만 답하십시오.

[이벤트 정보]
- 발생 시각: {_fmt(doc.get("@timestamp"))}
- 탐지 허니팟: {honeypot} ({honeypot_desc})
- 공격자 IP: {_fmt(doc.get("src_ip"))}
- 대상 포트: {_fmt(doc.get("dest_port"))}
- ML 분류 라벨: {_fmt(doc.get("ml_label"), "미분류")}
- ML 신뢰도: {_fmt(doc.get("ml_multi_conf"), "0")}%
- MITRE 위협 점수: {_fmt(doc.get("mitre_score"), "0")}/100
- MITRE 기법(1차 추정): {technique_s}

[작성 지침]
1. "summary_ko" — 비전문가 관리자도 이해할 수 있는 1~3문장 한국어 요약.
   무엇이 어디로 들어와 무엇을 시도했는지 구체적으로 쓰십시오.
2. "solution_ko" — 즉시 취할 수 있는 대응 조치를 1~3문장 한국어로.
   "모니터링하십시오" 같은 일반론 대신 실행 가능한 조치를 쓰십시오.
{severity_rule}{tail_no}. "ttp_inferred" — 추정되는 MITRE ATT&CK 기법 ID 배열 (예: ["T1110", "T1059"]).
   근거가 없으면 빈 배열로 두십시오. 기법 ID 형식만 쓰고 설명은 넣지 마십시오.

[언어 규칙]
모든 문자열 값은 **한국어로만** 작성하십시오. 한자나 중국어를 섞지 마십시오.
고유명사(IP, 포트, 허니팟명, MITRE ID)와 기술 용어는 원문 그대로 두어도 됩니다.

다른 텍스트 없이 아래 JSON 객체 하나만 출력하십시오:
{{
  "summary_ko": "한국어 요약",
  "solution_ko": "한국어 대응 방안",{severity_json}
  "ttp_inferred": ["T0000"]
}}"""


# Qwen-family models intermittently emit CJK ideographs mid-sentence in Korean
# output ("악意大시"). Prompt wording alone did not stop it (1/10 documents on
# the shipped model even with an explicit rule), so the output is checked
# instead: a hit is raised as a parse error, which the daemon's existing retry
# path handles, and a persistent failure lands on the deterministic fallback
# prose rather than shipping mixed-script text to the dashboard.
GROUP_FIELDS = ("honeypot", "ml_label", "dest_port")

# 리눅스 임시 포트 범위의 시작. 이 위로는 "공격자가 노린 서비스"가 아니라
# 그때그때 배정된 번호라, 포트 값을 그대로 키에 넣으면 그룹이 잘게 쪼개진다.
EPHEMERAL_PORT_MIN = 32768


def _port_bucket(value) -> str:
    """포트를 그룹 키 조각으로. 임시 포트는 하나로 접는다.

    실측(고위험 45,075건): 포트를 원값 그대로 쓰면 그룹이 1,400개인데 그중
    1,287개(92%)가 1건짜리다 — `Suricata|Intrusion|33414`, `|35532`, `|37352`
    처럼 임시 포트가 만들어낸 껍데기다. 이 그룹들은 전체의 2.86% 인데 해설
    호출의 92% 를 먹는다.

    접고 나면 **74개**가 된다(99.84% 절감). 6379(Redis)·3306(MySQL)·
    27017(MongoDB)·1433(MSSQL) 같은 서비스 포트는 32768 미만이라 그대로
    남는다 — 그것까지 묶으면 "Redis 침입" 과 "무작위 포트 스캔" 이 한 해설을
    쓰게 되어 내용이 뭉개진다. 1024 기준으로 접었을 때 실제로 그랬다.
    """
    if value in (None, ""):
        return "-"
    try:
        port = int(value)
    except (TypeError, ValueError):
        return str(value)
    return "ephemeral" if port >= EPHEMERAL_PORT_MIN else str(port)


def group_key(doc: dict) -> str:
    """이 문서가 속한 **공격 패턴**의 키.

    같은 허니팟에 같은 라벨로 같은 서비스를 두드리는 사건은 서사가 같다.
    실측: 고위험 45,075건이 74개 그룹이고 상위 2개(둘 다 포트 445)가 89.8% 를
    덮는다. 건당 해설하면 같은 이야기를 4만 번 쓰는 셈이고 61초씩 31.8일이
    드는데, 그룹 단위면 75분이다.

    ``mitre_score`` 를 키에 넣지 않는 이유: 점수는 라벨에서 파생되므로
    ``ml_label`` 이 같으면 항상 같다. 넣어도 그룹이 갈리지 않는다.
    """
    honeypot = doc.get("honeypot")
    label = doc.get("ml_label")
    return "|".join([
        str(honeypot) if honeypot not in (None, "") else "-",
        str(label) if label not in (None, "") else "-",
        _port_bucket(doc.get("dest_port")),
    ])


def build_group_prompt(doc: dict, ask_severity: bool = False) -> str:
    """패턴 단위 프롬프트 — **공격자 IP 와 발생 시각을 넣지 않는다.**

    건별 프롬프트(:func:`build_prompt`)는 IP 와 시각을 주입하고, 모델은 그걸
    본문에 그대로 박는다("2026년 5월 1일 …, 공격자 IP 203.0.113.99가 …").
    그 문장을 같은 그룹의 다른 사건에 재사용하면 **IP 와 시각이 전부 틀린다** —
    이 프로젝트가 쫓아온 조용한 실패와 같은 종류다.

    그래서 해설은 "이 유형의 공격이 무엇인가" 만 쓰게 하고, 사건별 구체값
    (IP·시각·포트)은 문서의 구조화 필드에 이미 있으므로 화면이 그쪽을 읽는다.
    모델이 IP 를 아예 보지 못하므로 지어낼 수도 없다.
    """
    honeypot = _fmt(doc.get("honeypot"))
    honeypot_desc = _HONEYPOT_KO.get(str(doc.get("honeypot") or "").lower(), "허니팟")
    technique = doc.get("mitre_technique")
    technique_s = ", ".join(technique) if isinstance(technique, list) else _fmt(technique, "미분류")

    # 포트도 그룹 키와 같은 규칙으로 쓴다. 대표 문서의 실제 포트를 그대로
    # 넣으면 임시 포트 그룹에서 모델이 "포트 44930 을 통해" 라고 쓰고, 그 문장이
    # 같은 그룹의 나머지 207건에 붙어 **전부 틀린 번호**가 된다 —
    # IP·시각을 뺀 것과 정확히 같은 이유다.
    bucket = _port_bucket(doc.get("dest_port"))
    port_desc = ("임시 포트(32768 이상, 사건마다 다름)" if bucket == "ephemeral"
                 else _fmt(doc.get("dest_port")))

    if ask_severity:
        severity_rule = (
            '3. "severity" — LOW, MEDIUM, HIGH, CRITICAL 중 하나.\n'
            "   **이 유형은 이미 고위험으로 선별된 것입니다.**\n"
            "   MITRE 위협 점수 기준을 반드시 지키십시오: 90점 이상은 CRITICAL,\n"
            "   70점 이상은 HIGH, 40점 이상은 MEDIUM. 이보다 낮게 매기지 마십시오.\n"
            '4. "risk_score" — 0에서 10 사이의 숫자. severity와 모순되지 않게.\n'
        )
        severity_json = '\n  "severity": "LOW|MEDIUM|HIGH|CRITICAL",\n  "risk_score": 0,'
        tail_no = "5"
    else:
        severity_rule = ""
        severity_json = ""
        tail_no = "3"

    return f"""당신은 한국어로 보고하는 침해대응(CERT) 분석가입니다.
아래는 허니팟에서 반복 관측되는 **공격 유형**입니다. 개별 사건이 아니라
이 유형 전체에 대한 설명을 지정된 JSON 형식으로만 작성하십시오.

[공격 유형]
- 탐지 허니팟: {honeypot} ({honeypot_desc})
- 대상 포트: {port_desc}
- ML 분류 라벨: {_fmt(doc.get("ml_label"), "미분류")}
- MITRE 위협 점수: {_fmt(doc.get("mitre_score"), "0")}/100
- MITRE 기법(1차 추정): {technique_s}

[작성 지침]
1. "summary_ko" — 비전문가 관리자도 이해할 수 있는 1~3문장 한국어 요약.
   이 포트와 허니팟 조합에서 공격자가 **무엇을 노리고 무엇을 시도하는지**를
   쓰십시오. 특정 IP·특정 시각·특정 포트 번호는 언급하지 마십시오 — 이 설명은
   같은 유형의 여러 사건에 함께 쓰이며, 사건별 IP·포트·시각은 화면이 따로
   보여줍니다. 대상 포트가 "임시 포트" 로 주어졌다면 번호를 지어내지 마십시오.
2. "solution_ko" — 즉시 취할 수 있는 대응 조치를 1~3문장 한국어로.
   "모니터링하십시오" 같은 일반론 대신 실행 가능한 조치를 쓰십시오.
{severity_rule}{tail_no}. "ttp_inferred" — 추정되는 MITRE ATT&CK 기법 ID 배열 (예: ["T1110", "T1059"]).
   근거가 없으면 빈 배열로 두십시오. 기법 ID 형식만 쓰고 설명은 넣지 마십시오.

[언어 규칙]
- 한국어와 영문 기술 용어만 쓰십시오. 한자를 쓰지 마십시오.
- JSON 외의 문장을 덧붙이지 마십시오.

{{
  "summary_ko": "한국어 요약",
  "solution_ko": "한국어 대응 방안",{severity_json}
  "ttp_inferred": ["T0000"]
}}"""


def _has_cjk(text: str) -> bool:
    return any("\u4e00" <= ch <= "\u9fff" for ch in text)


def _extract_json(text: str) -> dict:
    """Pull the first JSON object out of a model response."""
    s = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", s, re.DOTALL)
    if not m:
        raise ValueError(f"no JSON object in response: {s[:200]!r}")
    return json.loads(m.group(0))


def severity_from_score(mitre_score) -> str:
    """Deterministic severity used as the fallback when the LLM output is unusable."""
    try:
        score = float(mitre_score)
    except (TypeError, ValueError):
        score = 0.0
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def parse_response(text: str, doc: dict, ask_severity: bool = False) -> dict:
    """Validate/normalise the model output into the llm-analysis field contract.

    Raises ``ValueError`` if no JSON object can be recovered at all; the caller
    decides whether to retry or fall back.
    """
    raw = _extract_json(text)

    floor = severity_from_score(doc.get("mitre_score"))
    # `severity_source` tells a reader of the index who actually decided:
    #   score  — derived (the model was never asked, or gave nothing usable)
    #   llm    — the model's own verdict stood
    #   raised — the model went below the floor and was corrected
    source = "score"
    severity = floor
    risk = round(min(10.0, max(0.0, float(_fmt(doc.get("mitre_score"), "0") or 0) / 10.0)), 1)

    if ask_severity:
        claimed = str(raw.get("severity", "")).strip().upper()
        if claimed in SEVERITIES:
            # The model may raise severity above the score-derived floor (it
            # can see context the score misses) but never lower it: the daemon
            # only forwards events already past the MIN_SCORE gate, so a "LOW"
            # verdict contradicts the selection that produced the document.
            if SEVERITIES.index(claimed) >= SEVERITIES.index(floor):
                severity, source = claimed, "llm"
            else:
                severity, source = floor, "raised"

        try:
            risk = max(0.0, min(10.0, float(raw.get("risk_score"))))
        except (TypeError, ValueError):
            pass
        # Keep risk_score from contradicting severity — `risk_dist` and the
        # severity chart are read side by side on one screen.
        risk = max(risk, {"LOW": 0.0, "MEDIUM": 4.0, "HIGH": 7.0, "CRITICAL": 9.0}[severity])

    ttp = raw.get("ttp_inferred")
    if isinstance(ttp, str):
        ttp = [ttp]
    if not isinstance(ttp, list):
        ttp = []
    # Keep only things shaped like a MITRE technique id (T1110, T1110.001).
    ttp = [t for t in (str(x).strip().upper() for x in ttp) if re.fullmatch(r"T\d{4}(?:\.\d{3})?", t)]

    summary = str(raw.get("summary_ko") or "").strip()
    solution = str(raw.get("solution_ko") or "").strip()
    if not summary:
        raise ValueError("summary_ko missing from response")
    if _has_cjk(summary) or _has_cjk(solution):
        raise ValueError("response mixes Chinese characters into Korean prose")

    return {
        "summary_ko": summary,
        "solution_ko": solution or "추가 조치 권고가 생성되지 않았습니다. 원본 이벤트를 확인하십시오.",
        "severity": severity,
        "risk_score": round(risk, 1),
        "ttp_inferred": ttp,
        "severity_source": source,
    }


def fallback_result(doc: dict, reason: str) -> dict:
    """Deterministic result used when the LLM is unreachable or unparseable.

    Written to ES like any other result so the document is never silently
    dropped; ``llm_status`` marks it so operators can filter these out.
    """
    severity = severity_from_score(doc.get("mitre_score"))
    label = doc.get("ml_label") or "미분류"
    honeypot = doc.get("honeypot") or "허니팟"
    src = doc.get("src_ip") or "알 수 없는 IP"
    return {
        "summary_ko": (
            f"{src}에서 {honeypot}을(를) 대상으로 '{label}' 유형의 활동이 탐지되었습니다. "
            f"MITRE 위협 점수는 {_fmt(doc.get('mitre_score'), '0')}점입니다."
        ),
        "solution_ko": (
            "LLM 분석이 실패하여 규칙 기반 요약으로 대체되었습니다. "
            "해당 출발지 IP의 반복 시도 여부를 확인하고 필요 시 차단하십시오."
        ),
        "severity": severity,
        "risk_score": round(min(10.0, max(0.0, float(_fmt(doc.get("mitre_score"), "0") or 0) / 10.0)), 1),
        "ttp_inferred": [],
        "severity_source": "score",
        "llm_fallback_reason": reason,
    }
