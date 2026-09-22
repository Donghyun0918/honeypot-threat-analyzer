"""CSV 와 모델이 같은 인코더를 쓰는지 확인한다.

**왜 있나.** 카테고리 3종(protocol · source_honeypot · event_type)은 문자열이
아니라 정수 코드로 CSV 에 들어간다. 그 코드는 인코더를 만든 시점의 문서 집합에서
정해지므로, **인코더가 다르면 같은 값이 다른 숫자가 된다.**

2026-09-14 에 실제로 당했다(작업 로그 §4). 홀드아웃 CSV 를 학습과 다른 인코더로
뽑았고, event_type 코드 47개 중 22개가 밀려 200,000행 중 60,176행이 엉뚱한
카테고리로 들어갔다. 모델 성능이 92.5% 로 나와 "모델이 나쁘다" 로 읽혔는데,
실제로는 99.9% 였다. **틀린 수치가 그럴듯해서 사흘을 잘못 봤다.**

build_dataset.py 는 `--encoders-in` 으로 이걸 막지만, 학습(train.py)과
평가(eval_vs_rule.py)에는 방어가 없었다. 여기서 막는다.

검사는 두 겹이다:

1. **인코더끼리 대조** — CSV 옆 encoders.json 과 모델 쪽 encoders.json 이
   같은가. 가장 확실하지만 두 파일이 다 있어야 한다.
2. **코드 범위 대조** — CSV 에 인코더가 모르는 코드가 있는가.
   (인코더에 30개뿐인데 CSV 에 코드 46이 있으면 확실히 다른 인코더다.)
   옆에 encoders.json 이 없어도 돌아간다.
"""
import json
import sys
from pathlib import Path

CAT_COLS = ("protocol", "source_honeypot", "event_type")


def 인코더읽기(경로) -> dict | None:
    p = Path(경로)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def 옆에있는인코더(csv_경로) -> tuple[Path, dict | None]:
    """CSV 와 같은 폴더의 encoders.json. build_dataset.py 가 여기 남긴다."""
    p = Path(csv_경로).parent / "encoders.json"
    return p, 인코더읽기(p)


def 모델쪽인코더(모델_경로) -> tuple[Path, dict | None]:
    """모델 .pkl 과 같은 폴더의 encoders.json."""
    p = Path(모델_경로)
    p = (p.parent if p.suffix == ".pkl" else p) / "encoders.json"
    return p, 인코더읽기(p)


def _차이(a: dict, b: dict) -> list[str]:
    차이 = []
    for field in CAT_COLS:
        ma, mb = a.get(field, {}), b.get(field, {})
        if ma == mb:
            continue
        어긋남 = sum(1 for k in set(ma) & set(mb) if ma[k] != mb[k])
        차이.append(
            f"{field}: {len(ma)}개 vs {len(mb)}개"
            + (f", 공통 값 중 {어긋남}개가 다른 코드" if 어긋남 else "")
        )
    return 차이


def 대조(이름_a: str, enc_a: dict | None,
        이름_b: str, enc_b: dict | None, 강제: bool = False) -> bool:
    """두 인코더가 같은지 본다. 다르면 종료한다(강제면 경고만).

    반환값은 '실제로 대조했는가'. 한쪽이 없으면 False 다 — 통과가 아니다.
    """
    if enc_a is None or enc_b is None:
        없는쪽 = 이름_a if enc_a is None else 이름_b
        print(f"경고: {없는쪽} 에 encoders.json 이 없어 대조하지 못했다.",
              file=sys.stderr)
        return False

    차이 = _차이(enc_a, enc_b)
    if not 차이:
        print(f"인코더 일치 확인: {이름_a} ≡ {이름_b}")
        return True

    print("", file=sys.stderr)
    print(f"ERROR: 인코더가 다르다 — {이름_a} ≠ {이름_b}", file=sys.stderr)
    for d in 차이:
        print(f"  · {d}", file=sys.stderr)
    print("", file=sys.stderr)
    print("  같은 값이 서로 다른 숫자로 들어가 있다는 뜻이다. 이대로 재면", file=sys.stderr)
    print("  성능이 실제보다 낮게 나온다(작업 로그 §4: 92.5% ← 실제 99.9%).", file=sys.stderr)
    print("  홀드아웃은 학습에 쓴 인코더로 다시 뽑는다:", file=sys.stderr)
    print("    python build_dataset.py ... --encoders-in <학습에 쓴>/encoders.json",
          file=sys.stderr)
    print("  의도한 것이라면 --skip-encoder-check 를 준다.", file=sys.stderr)
    if 강제:
        print("  (--skip-encoder-check 로 계속 진행한다)", file=sys.stderr)
        return False
    sys.exit(2)


def 범위대조(df, enc: dict | None, csv_이름: str, 강제: bool = False) -> None:
    """CSV 안의 코드가 인코더 크기를 넘는지 본다.

    옆에 encoders.json 이 없을 때의 마지막 방어선이다. 넘는 코드가 있으면
    인코더가 다른 게 확실하다(작은 인코더로는 그 코드가 나올 수 없다).
    """
    if not enc:
        return
    넘침 = []
    for field in CAT_COLS:
        if field not in df.columns:
            continue
        크기 = len(enc.get(field, {}))
        if 크기 == 0:
            continue
        최대 = int(df[field].max()) if len(df) else -1
        if 최대 >= 크기:
            초과행 = int((df[field] >= 크기).sum())
            넘침.append(f"{field}: 인코더 {크기}개인데 코드 {최대} 가 있다"
                        f" ({초과행:,}행)")
    if not 넘침:
        return
    print("", file=sys.stderr)
    print(f"ERROR: {csv_이름} 의 코드가 인코더 범위를 넘는다", file=sys.stderr)
    for n in 넘침:
        print(f"  · {n}", file=sys.stderr)
    print("  다른 인코더로 만든 CSV 다. 작업 로그 §4 참조.", file=sys.stderr)
    if 강제:
        print("  (--skip-encoder-check 로 계속 진행한다)", file=sys.stderr)
        return
    sys.exit(2)
