"""Trickle honeypot events into Elasticsearch so live views have something to show.

Why this exists
---------------
``inject_sample_docs.py`` drops a batch and exits. That fills the dashboard
counters, but the attack map stays on its "Initializing…" screen forever:
``map_data`` (T-Pot's DataServer) only publishes events whose ``@timestamp``
falls inside a ~10 second trailing window, so a batch that finished a minute
ago produces no arcs. The map is not broken — nothing new is arriving.

This script keeps a slow, irregular stream going: a few events every few
seconds, timestamped *now*, from a rotating set of source countries. Enough
for the map to draw arcs continuously and for the counters to move while
someone is watching or recording.

Run it during a demo or a screen recording, stop it with Ctrl-C.

Usage:
  python integration-tests/demo_feed.py --host http://127.0.0.1:19200
  python integration-tests/demo_feed.py --rate 4 --burst 3   # 3건씩 4초마다
  python integration-tests/demo_feed.py --minutes 10         # 10분 뒤 자동 종료
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.request
from datetime import datetime, timezone

# 같은 디렉토리의 주입 스크립트에서 샘플·지오 정보를 그대로 가져온다.
# 두 벌로 관리하면 한쪽만 고쳐져 어긋난다.
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from inject_sample_docs import SAMPLES, geo_fields, post_bulk  # noqa: E402


def build_doc(now: datetime) -> tuple[str, dict]:
    label, base = random.choice(SAMPLES)
    doc = dict(base)
    doc.update(geo_fields(doc.get("src_ip", "")))
    doc["src_port"] = random.randint(1024, 65535)
    # 지금 시각으로 찍어야 map_data 의 트레일링 윈도우 안에 들어온다.
    doc["@timestamp"] = now.isoformat()
    doc["timestamp"] = doc["@timestamp"]
    doc["_expected_label"] = label
    return label, doc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="http://127.0.0.1:19200")
    ap.add_argument("--rate", type=float, default=5.0,
                    help="주입 간격(초). 실제로는 ±40%% 흔들어 기계적으로 보이지 않게 한다")
    ap.add_argument("--burst", type=int, default=2, help="한 번에 넣을 이벤트 수")
    ap.add_argument("--minutes", type=float, default=0,
                    help="이 시간이 지나면 종료(0이면 Ctrl-C 까지 계속)")
    args = ap.parse_args()

    deadline = time.time() + args.minutes * 60 if args.minutes else None
    total = 0
    print(f"데모 피드 시작 → {args.host}   {args.burst}건 / 약 {args.rate:.0f}초"
          f"{'   (' + str(args.minutes) + '분 후 종료)' if deadline else '   (Ctrl-C 로 종료)'}")

    try:
        while deadline is None or time.time() < deadline:
            now = datetime.now(timezone.utc)
            index = f"logstash-{now.strftime('%Y.%m.%d')}"
            lines = []
            labels = []
            for _ in range(args.burst):
                label, doc = build_doc(now)
                labels.append(label)
                lines.append(json.dumps({"index": {"_index": index}}))
                lines.append(json.dumps(doc))

            try:
                resp = post_bulk(args.host, "\n".join(lines) + "\n")
                ok = sum(1 for it in resp.get("items", [])
                         if it.get("index", {}).get("status", 0) < 300)
                total += ok
                print(f"  {now.strftime('%H:%M:%S')}  +{ok}건 ({', '.join(labels)})"
                      f"   누적 {total}", flush=True)
            except (urllib.error.URLError, OSError) as e:
                print(f"  {now.strftime('%H:%M:%S')}  주입 실패: {e}", flush=True)

            # 일정한 간격은 부자연스럽다 — 실제 공격 트래픽처럼 흔든다.
            time.sleep(max(0.5, args.rate * random.uniform(0.6, 1.4)))
    except KeyboardInterrupt:
        print(f"\n중단. 총 {total}건 주입.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
