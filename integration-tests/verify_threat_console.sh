#!/bin/sh
# 대시보드 수치 경로를 살아 있는 스택에 대고 확인한다.
#
# 단위 테스트(ThreatConsoleServiceTest)는 ES 를 타지 않는 계산만 본다. ES 질의
# 자체가 깨지는 경우 — §23-4 의 "src_ip 가 text 라 집계 전량 실패" 같은 것 — 는
# 여기서만 잡힌다. **그때 화면은 오류가 아니라 빈 값을 보여줬다.** 그래서 이
# 스크립트는 200 이 아니라 **내용이 있는지**를 본다.
#
#   ./verify_threat_console.sh                    (기본 localhost:8091)
#   API=http://127.0.0.1:8091 ./verify_threat_console.sh
set -e
API="${API:-http://localhost:8091}"
EMAIL="${EMAIL:-demo@jsp.test}"
PASS="${PASS:-demo1234}"

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
no()   { fail=$((fail+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

printf '대상: %s\n\n' "$API"

# ── 인증 ──────────────────────────────────────────────────────────────────
TOKEN=$(curl -s -X POST "$API/api/users/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

if [ -z "$TOKEN" ]; then
  printf '로그인 실패. 계정이 있는지, 연속 실패로 차단되지 않았는지 확인하세요.\n' >&2
  exit 1
fi
ok "로그인"

# 보관 로그로 시연하는 경우 기본 창(24h/7d)에는 데이터가 없다. 창을 넓혀 본다.
W='now-2y'

get() { curl -s -H "Authorization: Bearer $TOKEN" "$API$1"; }

# jq 없이도 돌게 파이썬으로 읽는다(사이드카 테스트와 같은 원칙).
jget() { python3 -c "
import json,sys
d=json.load(sys.stdin)
for k in '$2'.split('.'):
    d = d.get(k) if isinstance(d, dict) else None
    if d is None: break
print(d if not isinstance(d,(list,dict)) else len(d))
" 2>/dev/null || echo ""; }

# ── 개요 ──────────────────────────────────────────────────────────────────
OUT=$(get "/api/overview?since=$W")
N=$(printf '%s' "$OUT" | jget "" "total_events")
case "$N" in ''|0) no "overview: total_events 가 0 또는 없음 (창=$W)";; *) ok "overview: total_events=$N";; esac

# ── ML 통계 ───────────────────────────────────────────────────────────────
OUT=$(get "/api/ml-stats?since=$W")
N=$(printf '%s' "$OUT" | jget "" "labels")
case "$N" in ''|0) no "ml-stats: labels 버킷이 비었음";; *) ok "ml-stats: 라벨 $N종";; esac

# ── LLM 패턴 (패턴 단위 접기) ─────────────────────────────────────────────
OUT=$(get "/api/llm-patterns?since=$W&size=5")
N=$(printf '%s' "$OUT" | jget "" "pattern_count")
case "$N" in ''|0) no "llm-patterns: 패턴이 없음";; *) ok "llm-patterns: $N개";; esac

# 해설 문구가 실제로 실려 오는지. JsonData 를 convertValue 로 넘기면 조용히
# 빈 Map 이 되어 **빈 칸**이 나온다(§23). 200 만 봐서는 못 잡는다.
HAS=$(printf '%s' "$OUT" | python3 -c "
import json,sys
d=json.load(sys.stdin)
items=d.get('items') or []
print(sum(1 for i in items if (i.get('summary_ko') or '').strip()))
" 2>/dev/null || echo 0)
case "$HAS" in ''|0) no "llm-patterns: summary_ko 가 전부 비었음 — 해설이 사라지는 그 증상";; *) ok "llm-patterns: 해설 실림 $HAS건";; esac

# ── 자산 노출 대조 ────────────────────────────────────────────────────────
OUT=$(get "/api/exposure?since=$W&ports=22,445,65001")
N=$(printf '%s' "$OUT" | jget "" "items")
case "$N" in
  3) ok "exposure: 3개 포트 모두 반환(공격 없는 포트 포함)";;
  ''|0) no "exposure: 결과 없음";;
  *) no "exposure: 3개를 넣었는데 $N개만 돌아옴 — 조용한 포트가 사라지면 '확인 안 됨' 과 구분되지 않는다";;
esac

# src_ip 집계가 실제로 되는지(§23-4 의 전량 실패 지점)
IPS=$(printf '%s' "$OUT" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(sum((i.get('ip_count') or 0) for i in (d.get('items') or [])))
" 2>/dev/null || echo 0)
case "$IPS" in ''|0) no "exposure: ip_count 합계가 0 — src_ip 집계가 실패했을 수 있다(§23-4)";; *) ok "exposure: 고유 IP 합계 $IPS";; esac

# ── 인증 없이 접근되면 안 된다 ────────────────────────────────────────────
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$API/api/overview?since=$W")
case "$CODE" in 401|403) ok "인증 없이는 거부($CODE)";; *) no "인증 없이 $CODE 로 열려 있다";; esac

printf '\n통과 %d · 실패 %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
