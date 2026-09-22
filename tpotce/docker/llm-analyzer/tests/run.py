#!/usr/bin/env python3
"""pytest 없이 테스트를 돌린다.

사이드카 이미지에는 pytest 가 없고, 팀원 PC 에도 있으리라는 보장이 없다.
테스트를 돌리는 데 준비물이 필요하면 아무도 안 돌린다 — 표준 라이브러리만 쓴다.

    python3 tests/run.py
"""
import importlib.util
import sys
import traceback
from pathlib import Path

여기 = Path(__file__).resolve().parent


def 모듈불러오기(경로: Path):
    spec = importlib.util.spec_from_file_location(경로.stem, 경로)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    통과 = 실패 = 0
    실패목록 = []

    for 파일 in sorted(여기.glob("test_*.py")):
        mod = 모듈불러오기(파일)
        이름들 = [n for n in dir(mod) if n.startswith("test_")]
        print(f"\n{파일.name}  ({len(이름들)}개)")
        for 이름 in 이름들:
            try:
                getattr(mod, 이름)()
            except Exception:
                실패 += 1
                실패목록.append((파일.name, 이름, traceback.format_exc()))
                print(f"  \033[31m✗\033[0m {이름}")
            else:
                통과 += 1
                print(f"  \033[32m✓\033[0m {이름}")

    for 파일명, 이름, tb in 실패목록:
        print(f"\n\033[31m─── {파일명}::{이름}\033[0m\n{tb}")

    print(f"\n통과 {통과} · 실패 {실패}")
    return 1 if 실패 else 0


if __name__ == "__main__":
    sys.exit(main())
