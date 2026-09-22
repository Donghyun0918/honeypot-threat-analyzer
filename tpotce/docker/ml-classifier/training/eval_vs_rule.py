"""
모델이 규칙을 얼마나 재현하는가 — 홀드아웃 실 ES 문서 기준.

이 프로젝트에서 정답 라벨은 rule_label.py 가 만든다. 그래서 모델의 상한은
"규칙 재현 100%" 이고, holdout accuracy 는 학습 분포 안에서만 유효하다.
의미 있는 숫자는 **학습에 쓰지 않은 실 문서에서 규칙과 얼마나 합의하는가** 다.

DATASET_FINDINGS.md 가 127건으로 쟀던 것(v2 35.4% · v3 61.4%)을 여기서는
수십만 건으로 재고, 모델 여러 개를 나란히 비교한다.

사용:
    python eval_vs_rule.py --csv work/holdout.csv \\
        --model 현행=data/.../models/multi_model.pkl \\
        --model 실데이터학습=work-real/models_real/multi_model.pkl
"""

import argparse
import sys
from collections import Counter, defaultdict

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, "/dist")
import feature_extract  # noqa: E402

import encoder_guard  # noqa: E402


def 평가(이름: str, 경로: str, X: np.ndarray, y: np.ndarray) -> dict:
    m = joblib.load(경로)
    pred = m.predict(X)
    pred = np.asarray([str(p) for p in pred])

    맞음 = pred == y
    micro = 맞음.mean() * 100

    라벨별 = {}
    오답 = defaultdict(Counter)
    for lbl in sorted(set(y)):
        sel = y == lbl
        라벨별[lbl] = (맞음[sel].mean() * 100, int(sel.sum()))
        for p in pred[sel][~맞음[sel]]:
            오답[lbl][p] += 1

    macro = sum(v[0] for v in 라벨별.values()) / len(라벨별)
    return {"이름": 이름, "micro": micro, "macro": macro, "라벨별": 라벨별, "오답": 오답}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="홀드아웃 특징 CSV (build_dataset.py 출력)")
    ap.add_argument("--model", action="append", required=True,
                    help="이름=경로 형식. 여러 번 줄 수 있다.")
    ap.add_argument("--skip-encoder-check", action="store_true",
                    help="인코더 대조를 건너뛴다. 일부러 다른 인코더로 재볼 때만.")
    a = ap.parse_args()

    df = pd.read_csv(a.csv)
    X = df[feature_extract.FEATURE_COLS].to_numpy()
    y = df["label"].astype(str).to_numpy()

    # 인코더 대조 — 평가 **전에** 한다. §4 에서는 잘못된 수치가 먼저 나오고
    # 그게 그럴듯해서 사흘을 잘못 봤다. 숫자를 보여주기 전에 막아야 한다.
    csv_enc_경로, csv_enc = encoder_guard.옆에있는인코더(a.csv)
    for spec in a.model:
        이름, _, 경로 = spec.partition("=")
        모델_enc_경로, 모델_enc = encoder_guard.모델쪽인코더(경로)
        encoder_guard.대조(f"CSV({csv_enc_경로})", csv_enc,
                          f"모델 {이름}({모델_enc_경로})", 모델_enc,
                          강제=a.skip_encoder_check)
        encoder_guard.범위대조(df, 모델_enc, a.csv, 강제=a.skip_encoder_check)
    print()

    print(f"홀드아웃 {len(df):,}건 · 특징 {len(feature_extract.FEATURE_COLS)}개")
    print("규칙 라벨 분포:", dict(Counter(y).most_common()))
    print()

    결과 = []
    for spec in a.model:
        이름, _, 경로 = spec.partition("=")
        try:
            결과.append(평가(이름, 경로, X, y))
        except Exception as e:  # noqa: BLE001
            print(f"  ! {이름}: 평가 실패 — {e}")

    if not 결과:
        return 1

    라벨들 = sorted(결과[0]["라벨별"])
    w = max(len(r["이름"]) for r in 결과) + 2

    print(f"{'모델':<{w}}{'micro':>9}{'macro':>9}   " + "".join(f"{l:>14}" for l in 라벨들))
    print("─" * (w + 18 + 14 * len(라벨들)))
    for r in 결과:
        row = f"{r['이름']:<{w}}{r['micro']:>8.1f}%{r['macro']:>8.1f}%   "
        row += "".join(f"{r['라벨별'][l][0]:>13.1f}%" for l in 라벨들)
        print(row)
    print("─" * (w + 18 + 14 * len(라벨들)))
    print("건수" + " " * (w - 4) + " " * 18 + "   " + "".join(f"{결과[0]['라벨별'][l][1]:>14,}" for l in 라벨들))

    for r in 결과:
        print(f"\n[{r['이름']}] 주요 오답 (규칙 → 모델)")
        for lbl in 라벨들:
            top = r["오답"][lbl].most_common(2)
            if top:
                print("   " + f"{lbl:<14}" + " · ".join(f"{k} {v:,}" for k, v in top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
