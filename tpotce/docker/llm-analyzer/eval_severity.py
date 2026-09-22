"""Measure how often the LLM's own severity verdict is usable.

``llm-analyzer`` clamps severity to a floor derived from ``mitre_score``
(``prompt_ko.parse_response``), and every document written so far came back
``severity_adjusted: true`` — i.e. the model's own verdict was below the floor
every single time. That is either a prompt problem or a model-capability
problem, and the two call for different fixes, so measure before changing.

Runs a set of real ``ml-analysis-*`` documents through one or more prompt
variants and reports, per variant:

  raw_ok    model's severity already matched the score-derived floor
  raw_low   model went below the floor (the guard had to raise it)
  raw_high  model went above the floor (allowed — model saw extra risk)
  parse_err response unusable

Usage:
  python eval_severity.py --es http://localhost:19200 --n 12
  python eval_severity.py --n 12 --variants current,fewshot,score_free
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist"))

import prompt_ko  # noqa: E402
import providers  # noqa: E402


# ── prompt variants ───────────────────────────────────────────────────────
FEWSHOT_BLOCK = """
[판정 예시]
입력: MITRE 위협 점수 92, 라벨 Malware, 허니팟 dionaea
출력: {"severity": "CRITICAL", "risk_score": 9.2}

입력: MITRE 위협 점수 78, 라벨 Intrusion, 허니팟 suricata
출력: {"severity": "HIGH", "risk_score": 7.8}

입력: MITRE 위협 점수 70, 라벨 Brute Force, 허니팟 cowrie
출력: {"severity": "HIGH", "risk_score": 7.0}

위 예시처럼 severity 는 점수 구간을 그대로 따르고,
risk_score 는 대체로 점수를 10으로 나눈 값에 가깝게 매기십시오.
"""


def build(variant: str, doc: dict) -> str:
    # 이 하네스의 목적이 "모델이 severity 를 판정할 수 있는가" 이므로
    # 반드시 물어보는 프롬프트를 써야 한다. build_prompt 의 기본값은
    # ask_severity=False(운영 기본값)라 그대로 쓰면 묻지도 않고
    # "답이 없다"고 세게 된다.
    base = prompt_ko.build_prompt(doc, ask_severity=True)
    if variant == "current":
        return base
    if variant == "fewshot":
        return base.replace("[언어 규칙]", FEWSHOT_BLOCK + "\n[언어 규칙]")
    if variant == "score_free":
        # Ask only for prose; severity/risk are computed from mitre_score.
        return (
            base.split("[작성 지침]")[0]
            + """[작성 지침]
1. "summary_ko" — 비전문가 관리자도 이해할 수 있는 1~3문장 한국어 요약.
2. "solution_ko" — 즉시 취할 수 있는 대응 조치를 1~3문장 한국어로.
3. "ttp_inferred" — 추정되는 MITRE ATT&CK 기법 ID 배열. 근거 없으면 빈 배열.

[언어 규칙]
모든 문자열 값은 한국어로만 작성하십시오. 한자나 중국어를 섞지 마십시오.

다른 텍스트 없이 아래 JSON 객체 하나만 출력하십시오:
{
  "summary_ko": "한국어 요약",
  "solution_ko": "한국어 대응 방안",
  "ttp_inferred": ["T0000"]
}"""
        )
    raise SystemExit(f"unknown variant: {variant}")


def fetch_docs(es: str, n: int) -> list[dict]:
    body = json.dumps({
        "size": n,
        "sort": [{"mitre_score": {"order": "desc"}}],
        "query": {"bool": {"filter": [{"range": {"mitre_score": {"gte": 70}}}]}},
    }).encode()
    req = urllib.request.Request(f"{es}/ml-analysis-*/_search", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        hits = json.loads(r.read())["hits"]["hits"]
    return [h["_source"] for h in hits]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--es", default="http://localhost:19200")
    ap.add_argument("--n", type=int, default=12)
    ap.add_argument("--variants", default="current,fewshot,score_free")
    args = ap.parse_args()

    docs = fetch_docs(args.es, args.n)
    if not docs:
        print("고위험 문서가 없습니다 (mitre_score >= 70)")
        return 1

    provider = providers.build_provider()
    print(f"모델 {provider.name}/{provider.model} · 문서 {len(docs)}건\n")

    for variant in args.variants.split(","):
        tally = collections.Counter()
        korean_issues = 0
        t0 = time.time()
        for doc in docs:
            floor = prompt_ko.severity_from_score(doc.get("mitre_score"))
            try:
                raw = provider.complete(build(variant, doc))
                obj = prompt_ko._extract_json(raw)
            except Exception:
                tally["parse_err"] += 1
                continue

            text = f"{obj.get('summary_ko', '')} {obj.get('solution_ko', '')}"
            # CJK ideographs that are not Hangul — qwen leaks these
            if any("一" <= ch <= "鿿" for ch in text):
                korean_issues += 1

            if variant == "score_free":
                tally["n/a"] += 1
                continue

            sev = str(obj.get("severity", "")).strip().upper()
            if sev not in prompt_ko.SEVERITIES:
                tally["parse_err"] += 1
            elif sev == floor:
                tally["raw_ok"] += 1
            elif prompt_ko.SEVERITIES.index(sev) < prompt_ko.SEVERITIES.index(floor):
                tally["raw_low"] += 1
            else:
                tally["raw_high"] += 1

        dur = time.time() - t0
        total = sum(tally.values()) or 1
        acc = 100.0 * (tally["raw_ok"] + tally["raw_high"]) / total
        bits = " · ".join(f"{k}={v}" for k, v in sorted(tally.items()) if v)
        note = "" if variant == "score_free" else f"  가드 불필요 {acc:.0f}%"
        print(f"  {variant:<11} {bits}{note}   한자혼입 {korean_issues}/{len(docs)}  ({dur:.0f}s)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
