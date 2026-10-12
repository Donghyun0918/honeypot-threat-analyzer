"""
T-Pot 원본 로그 → logstash 배치 임포트용 스테이징

왜 필요한가: T-Pot 의 logstash.conf 는 허니팟마다 *현재* 로그 파일 하나만
바라본다(`/data/cowrie/log/cowrie.json`). 그런데 보관된 로그는 로테이션돼
있어서 본체가 `.gz` 와 날짜별 파일에 흩어져 있다 — cowrie 의 경우 현재
파일은 64KB 인데 로테이션분까지 합치면 92,866 이벤트다. logstash 의 file
input 은 .gz 를 못 읽으므로, 여기서 미리 풀어서 하나로 합친다.

glob 패턴은 logs/convert_logs.py 와 **일부러 동일하게** 맞췄다. 그래야
적재 결과를 logs/csv/*.csv 행수와 그대로 대조할 수 있다.

p0f 는 제외한다. 170만 행으로 전체의 절반인데 수동 핑거프린팅 기록이라
공격 분석에 기여하는 바에 비해 색인 비용이 크다.

사용:
    python3 stage_logs.py --src /path/to/logs --dst /path/to/logs-staged
"""

import argparse
import gzip
import shutil
import sys
from pathlib import Path

# 허니팟 → (수집 glob, logstash 가 기대하는 파일명)
#   glob 은 convert_logs.py 와 동일, 파일명은 logstash.conf 의 path 와 동일.
대상 = {
    "adbhoney":      ("adbhoney.json*",      "adbhoney.json"),
    "ciscoasa":      ("ciscoasa.log*",       "ciscoasa.log"),
    "conpot":        ("*.json*",             "conpot_all.json"),   # conf 는 *.json glob
    "cowrie":        ("cowrie.json*",        "cowrie.json"),
    "dionaea":       ("dionaea.json*",       "dionaea.json"),
    "elasticpot":    ("elasticpot.json*",    "elasticpot.json"),
    "fatt":          ("fatt.log*",           "fatt.log"),
    "h0neytr4p":     ("log.json*",           "log.json"),
    "heralding":     ("auth.csv*",           "auth.csv"),
    "honeyaml":      ("honeyaml.log*",       "honeyaml.log"),
    "honeytrap":     ("attackers.json*",     "attackers.json"),
    "ipphoney":      ("ipphoney.json*",      "ipphoney.json"),
    "mailoney":      ("commands.log*",       "commands.log"),
    "miniprint":     ("miniprint.json*",     "miniprint.json"),
    "redishoneypot": ("redishoneypot.log*",  "redishoneypot.log"),
    "sentrypeer":    ("sentrypeer*.json*",   "sentrypeer.json"),
    "suricata":      ("eve.json*",           "eve.json"),
    "tanner":        ("tanner_report.json*", "tanner_report.json"),
}

제외접미 = {".db", ".pem", ".tgz"}


def 열기(p: Path):
    if p.suffix == ".gz":
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return open(p, "r", encoding="utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="T-Pot 원본 로그 디렉토리")
    ap.add_argument("--dst", required=True, help="스테이징 출력 디렉토리")
    a = ap.parse_args()

    src, dst = Path(a.src), Path(a.dst)
    if not src.is_dir():
        print(f"원본 디렉토리가 없습니다: {src}", file=sys.stderr)
        return 1

    if dst.exists():
        shutil.rmtree(dst)   # 두 번 돌려도 중복 적재되지 않도록

    합계 = 0
    print(f"{'허니팟':<16}{'파일':>6}{'줄':>12}")
    print("─" * 34)
    for 이름, (패턴, 출력명) in sorted(대상.items()):
        base = src / 이름 / "log"
        if not base.is_dir():
            print(f"{이름:<16}{'—':>6}{'없음':>12}")
            continue
        files = [f for f in sorted(base.glob(패턴))
                 if f.is_file() and f.suffix not in 제외접미]
        if not files:
            print(f"{이름:<16}{0:>6}{0:>12}")
            continue

        out = dst / 이름 / "log" / 출력명
        out.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with open(out, "w", encoding="utf-8") as w:
            for f in files:
                with 열기(f) as r:
                    for line in r:
                        if line.strip():
                            w.write(line if line.endswith("\n") else line + "\n")
                            n += 1
        합계 += n
        print(f"{이름:<16}{len(files):>6}{n:>12,}")

    print("─" * 34)
    print(f"{'합계':<16}{'':>6}{합계:>12,}")
    print(f"\n스테이징 완료 → {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
