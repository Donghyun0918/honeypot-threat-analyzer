"""한국어 해설 파싱 회귀 테스트.

7장에서 LLM 에게서 위험도 판정을 회수했다. 그 결정이 코드에 남아 있는지,
그리고 재시도를 유발해야 할 응답이 그대로 통과하지 않는지 확인한다.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "dist"))

import prompt_ko  # noqa: E402


def 문서(score=92, **kw):
    d = {"mitre_score": score, "ml_label": "Intrusion", "src_ip": "203.0.113.5",
         "honeypot": "Cowrie", "dest_port": 22}
    d.update(kw)
    return d


def 응답(**kw) -> str:
    import json
    base = {"summary_ko": "SSH 무단 접근 시도가 있었습니다.",
            "solution_ko": "해당 IP 를 차단하세요.",
            "ttp_inferred": "T1110"}
    base.update(kw)
    return json.dumps(base, ensure_ascii=False)


# ── 점수 → 위험도 대응표 ─────────────────────────────────────────────────
def test_위험도는_점수에서_계산된다():
    assert prompt_ko.severity_from_score(95) == "CRITICAL"
    assert prompt_ko.severity_from_score(70) == "HIGH"
    assert prompt_ko.severity_from_score(40) == "MEDIUM"
    assert prompt_ko.severity_from_score(0) == "LOW"


def test_점수가_없거나_이상해도_LOW_로_떨어진다():
    for bad in (None, "", "높음", float("nan")):
        assert prompt_ko.severity_from_score(bad) in prompt_ko.SEVERITIES


# ── 실패: mitre_score 92 인데 모델이 LOW 를 반환했다 ─────────────────────
# 3B 는 고위험 10건 중 10건을 낮게 매겼다. 그 값을 그대로 저장하면 진짜 침입이
# 대시보드에서 조용히 사라진다. 그래서 위험도는 모델에게 묻지 않는 것이 기본이다.
def test_기본값은_모델에게_위험도를_묻지_않는다():
    r = prompt_ko.parse_response(응답(severity="LOW"), 문서(score=92))
    assert r["severity"] == "CRITICAL"
    assert r["severity_source"] == "score"


# 더 강한 모델로 되돌릴 때(LLM_SEVERITY=model)도 **내려잡는 것은 막는다.**
# 올려잡는 것은 받아들인다 — 모델이 점수가 못 본 맥락을 봤을 수 있다.
def test_모델이_점수보다_낮게_잡으면_점수로_올린다():
    r = prompt_ko.parse_response(응답(severity="LOW"), 문서(score=92), ask_severity=True)
    assert r["severity"] == "CRITICAL"
    assert r["severity_source"] == "raised"


def test_모델이_점수보다_높게_잡으면_받아들인다():
    r = prompt_ko.parse_response(응답(severity="CRITICAL"), 문서(score=45), ask_severity=True)
    assert r["severity"] == "CRITICAL"
    assert r["severity_source"] == "llm"


# ── 실패: 한국어 문장에 한자가 섞였다 ────────────────────────────────────
# 프롬프트에 "한국어로만" 이라고 써도 10건 중 1건에서 났다. 지시가 아니라
# 출력 검사로 막는다 — 파싱 오류로 처리해 기존 재시도 경로가 다시 시도한다.
def test_한자가_섞이면_파싱을_거부한다():
    try:
        prompt_ko.parse_response(응답(summary_ko="공격자가 惡意的 명령을 실행했습니다."), 문서())
    except Exception:
        return
    raise AssertionError("한자가 섞인 응답이 그대로 통과했다")


def test_순수_한국어는_통과한다():
    r = prompt_ko.parse_response(응답(), 문서())
    assert "무단" in r["summary_ko"]


# ── 폴백은 소비자 계약을 지켜야 한다 ─────────────────────────────────────
# 폴백은 실패 경로다. 여기서 필드가 빠지면 대시보드가 빈 칸을 그리는데,
# 그건 "분석 결과가 없다"가 아니라 "분석했는데 내용이 없다"로 보인다.
def test_폴백도_필드를_전부_채우고_한자가_없다():
    r = prompt_ko.fallback_result(문서(score=92), "모델 응답 없음")
    for k in ("summary_ko", "solution_ko", "severity", "severity_source"):
        assert r.get(k), k
    assert r["severity"] == "CRITICAL"
    assert not prompt_ko._has_cjk(r["summary_ko"] + r["solution_ko"])


# ── JSON 이 아닌 응답을 견딘다 ───────────────────────────────────────────
# 모델은 종종 ```json 울타리나 설명 문장을 앞뒤에 붙인다.
def test_코드_울타리와_잡담이_섞여도_JSON_을_찾아낸다():
    본문 = "네, 분석했습니다.\n```json\n" + 응답() + "\n```\n도움이 되었길 바랍니다."
    r = prompt_ko.parse_response(본문, 문서())
    assert "무단" in r["summary_ko"]


# ── 패턴 단위 해설의 안전 조건 ───────────────────────────────────────────
# 같은 패턴(허니팟|라벨|포트)의 해설을 여러 사건에 나눠 쓰면 LLM 호출이
# 96.9% 줄어든다(실측: 고위험 45,075건 → 1,400그룹, 상위 3개가 90% 커버).
#
# 그런데 건별 프롬프트는 IP 와 시각을 주입하고 모델은 그걸 본문에 그대로
# 박는다("2026년 5월 1일 …, 공격자 IP 203.0.113.99가 …"). 그 문장을 재사용하면
# **나머지 전부에 틀린 IP 와 틀린 시각이 박힌다** — 화면에는 멀쩡해 보이는,
# 이 프로젝트가 계속 쫓아온 종류의 조용한 실패다.
#
# 그래서 패턴 프롬프트는 IP·시각을 아예 넣지 않는다. 모델이 못 본 값은 지어낼
# 수도 없다. 아래 두 테스트가 그 계약을 못 박는다.
def test_패턴_프롬프트에는_IP_와_시각이_들어가지_않는다():
    d = 문서(src_ip="203.0.113.99", **{"@timestamp": "2026-05-01T14:23:07Z"})
    p = prompt_ko.build_group_prompt(d)
    assert "203.0.113.99" not in p, "패턴 해설에 공격자 IP 가 새어 들어갔다"
    assert "2026-05-01" not in p, "패턴 해설에 발생 시각이 새어 들어갔다"
    # 건별 프롬프트는 반대로 둘 다 들어 있어야 한다(비교 대상).
    b = prompt_ko.build_prompt(d)
    assert "203.0.113.99" in b and "2026-05-01" in b


def test_패턴_프롬프트도_포트와_허니팟은_유지한다():
    # 서사를 쓰려면 이 둘은 필요하다. 그룹 키의 구성요소이기도 하다.
    p = prompt_ko.build_group_prompt(문서(honeypot="Dionaea", dest_port=445))
    assert "445" in p and "Dionaea" in p


def test_그룹_키는_허니팟_라벨_포트로만_갈린다():
    a = 문서(src_ip="203.0.113.1", **{"@timestamp": "2026-05-01T00:00:00Z"})
    b = 문서(src_ip="198.51.100.7", **{"@timestamp": "2026-05-06T23:59:59Z"})
    assert prompt_ko.group_key(a) == prompt_ko.group_key(b), \
        "IP·시각이 그룹을 가르면 재사용 효과가 사라진다"
    assert prompt_ko.group_key(문서(dest_port=445)) != prompt_ko.group_key(문서(dest_port=22))
    assert prompt_ko.group_key(문서(ml_label="Malware")) != prompt_ko.group_key(문서(ml_label="Intrusion"))


def test_그룹_키는_빈_값에도_죽지_않는다():
    assert prompt_ko.group_key({}) == "-|-|-"
    # 빈 문자열은 "-" 로 접지만 포트 0 은 실제 값이므로 살린다.
    assert prompt_ko.group_key({"honeypot": "", "dest_port": 0}) == "-|-|0"


# ── 임시 포트는 그룹을 쪼개지 말아야 한다 ────────────────────────────────
# 포트를 원값으로 쓰면 그룹 1,400개 중 1,287개(92%)가 1건짜리였다. 전부
# Suricata|Intrusion|33414 같은 임시 포트 껍데기이고, 전체 사건의 2.86% 인데
# 해설 호출의 92% 를 먹는다. 접으면 74개가 된다.
def test_임시_포트는_한_그룹으로_접힌다():
    a = prompt_ko.group_key(문서(dest_port=33414))
    b = prompt_ko.group_key(문서(dest_port=52341))
    assert a == b and a.endswith("|ephemeral")


# 다만 서비스 포트까지 접으면 안 된다. 1024 기준으로 묶었더니 Redis(6379)·
# MySQL(3306)·MongoDB(27017) 침입이 무작위 포트 스캔과 한 해설을 쓰게 됐다.
def test_서비스_포트는_각자_그룹을_유지한다():
    keys = {p: prompt_ko.group_key(문서(dest_port=p))
            for p in (445, 6379, 3306, 27017, 1433, 22)}
    assert len(set(keys.values())) == len(keys), f"서비스 포트가 뭉쳤다: {keys}"
    for p in keys:
        assert "ephemeral" not in keys[p]


def test_포트가_숫자가_아니어도_죽지_않는다():
    assert prompt_ko.group_key(문서(dest_port="알 수 없음")).endswith("|알 수 없음")
    assert prompt_ko.group_key(문서(dest_port=None)).endswith("|-")


# 임시 포트 그룹에는 구체적 번호를 주면 안 된다. 대표 문서의 포트(44930)를
# 그대로 넣었더니 모델이 "포트 44930 을 통해" 라고 썼고, 그 문장이 같은 그룹의
# 나머지 207건에 붙어 전부 틀린 번호가 됐다 — IP·시각을 뺀 것과 같은 이유다.
def test_임시_포트_그룹에는_구체적_번호를_주지_않는다():
    p = prompt_ko.build_group_prompt(문서(dest_port=44930))
    assert "44930" not in p, "임시 포트 번호가 프롬프트에 새어 들어갔다"
    assert "임시 포트" in p


def test_서비스_포트는_번호를_그대로_준다():
    # 445 는 서사에 꼭 필요한 정보다. 이건 가려선 안 된다.
    assert "445" in prompt_ko.build_group_prompt(문서(dest_port=445))
