"""Cowrie 세션 포트 채우기 회귀 테스트.

    python3 tests/run.py      (사이드카 이미지 안에서 — classify 는 numpy·elasticsearch 를 부른다)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "dist"))

import classify  # noqa: E402


def _포트(**doc):
    return classify._build_action(doc, "logstash-x", "id", {})["_source"]["dest_port"]


# ── 실패: Cowrie 명령·다운로드 행에 dest_port 가 없었다 ──────────────────────
# session.connect 에만 포트가 있어서, 같은 세션의 고위험(명령 실행·파일 다운로드)이
# 포트 집계에서 전부 빠졌다. 4~5월 수집분 고위험 16건 → 표 5-9 의 "22번 고위험 0건".
def test_같은_세션의_뒤_행은_connect_의_포트를_물려받는다():
    classify._SESSION_PORT.clear()
    assert _포트(type="Cowrie", session="s1", eventid="cowrie.session.connect", dest_port=22) == 22
    assert _포트(type="Cowrie", session="s1", eventid="cowrie.session.file_download") == 22


def test_세션이_다르면_섞이지_않는다():
    classify._SESSION_PORT.clear()
    _포트(type="Cowrie", session="a", dest_port=22)
    _포트(type="Cowrie", session="b", dest_port=23)
    assert _포트(type="Cowrie", session="b", eventid="cowrie.command.input") == 23
    assert _포트(type="Cowrie", session="c", eventid="cowrie.command.input") is None, \
        "connect 를 못 본 세션에 아무 포트나 붙이면 집계가 거꾸로 틀린다"


def test_다른_허니팟은_그대로_둔다():
    classify._SESSION_PORT.clear()
    _포트(type="Cowrie", session="x", dest_port=22)
    assert _포트(type="Suricata", session="x") is None, "session 은 Cowrie 필드다"


def test_기억은_상한을_넘지_않는다():
    classify._SESSION_PORT.clear()
    for i in range(classify._SESSION_PORT_MAX + 10):
        _포트(type="Cowrie", session=f"s{i}", dest_port=22)
    assert len(classify._SESSION_PORT) == classify._SESSION_PORT_MAX
    assert _포트(type="Cowrie", session="s0") is None, "가장 오래된 세션부터 잊는다"
