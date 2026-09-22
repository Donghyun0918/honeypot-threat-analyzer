#!/usr/bin/env bash
# 정사평 — 처음 받은 사람이 실행하는 준비 스크립트.
#
# 저장소를 받은 뒤 이 스크립트 하나로 스택이 뜨는 상태까지 간다.
# 여러 번 실행해도 안전하다(이미 된 것은 건너뛴다).
#
#   ./setup.sh            준비 + 기동 + 시연 데이터
#   ./setup.sh --no-seed  데이터 주입 없이 기동만
#   ./setup.sh --check    환경만 점검하고 종료
#
# (셸 변수명에는 ASCII 만 쓴다 — bash 는 비ASCII 식별자를 허용하지 않는다.)

set -euo pipefail
cd "$(dirname "$0")"

C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
say()  { printf '  %s\n' "$*"; }
ok()   { printf '  %s✓%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_YEL" "$C_OFF" "$*"; }
die()  { printf '  %s✗%s %s\n' "$C_RED" "$C_OFF" "$*"; exit 1; }
head_() { printf '\n%s\n' "$*"; }

SEED=1
CHECK_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --no-seed) SEED=0 ;;
    --check)   CHECK_ONLY=1 ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "알 수 없는 옵션: $arg" ;;
  esac
done

# ─────────────────────────────────────────────────────────────────────────────
head_ "1. 환경 점검"

command -v docker >/dev/null 2>&1 || die "docker 가 없습니다. Docker Desktop 을 설치하세요."
docker info >/dev/null 2>&1 || die "docker 데몬에 연결할 수 없습니다. Docker Desktop 이 실행 중인지 확인하세요."
ok "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '')"

docker compose version >/dev/null 2>&1 || die "docker compose(v2) 가 필요합니다."
ok "docker compose"

# 메모리 — Elasticsearch 와 Ollama 를 같이 띄우려면 6GB 는 있어야 한다.
if [ -r /proc/meminfo ]; then
  mem_mb=$(( $(awk '/MemTotal/{print $2}' /proc/meminfo) / 1024 ))
  if [ "$mem_mb" -lt 6000 ]; then
    warn "메모리 ${mem_mb}MB — Elasticsearch 와 Ollama 를 같이 띄우기엔 빠듯합니다(6GB 이상 권장)."
  else
    ok "메모리 ${mem_mb}MB"
  fi
fi

# 디스크 — 이미지 + LLM 모델로 약 12GB
disk_gb=$(df -BG . 2>/dev/null | awk 'NR==2{gsub("G","",$4); print $4}' || echo 99)
if [ "${disk_gb:-99}" -lt 12 ]; then
  warn "디스크 여유 ${disk_gb}GB — 이미지와 LLM 모델에 12GB 정도 필요합니다."
else
  ok "디스크 여유 ${disk_gb}GB"
fi

# 포트 충돌 — 다른 스택이 떠 있으면 메모리도 같이 부족해진다.
busy=""
for port in 8002 8091 19300 5434 11435; do
  if (command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ":${port} ") ||
     (command -v lsof >/dev/null 2>&1 && lsof -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1); then
    busy="$busy $port"
  fi
done
if [ -n "$busy" ]; then
  warn "이미 쓰이는 포트:$busy — 기존 스택을 내리거나 포트를 바꾸세요."
else
  ok "포트 8002 / 8091 / 19300 / 5434 / 11435 비어 있음"
fi

[ "$CHECK_ONLY" = "1" ] && { head_ "점검만 수행했습니다."; exit 0; }

# ─────────────────────────────────────────────────────────────────────────────
head_ "2. 설정 파일"

if [ -f .env ]; then
  ok ".env 이미 있음 (건드리지 않음)"
else
  cp .env.example .env
  # JWT 서명 키는 사람마다 달라야 한다. 비어 있으면 기동할 때마다 임의 키가
  # 만들어져 재기동 시 로그인이 풀린다.
  secret=$(openssl rand -base64 48 2>/dev/null | tr -d '\n' || head -c 48 /dev/urandom | base64 | tr -d '\n')
  # 서비스 간 호출용 공유 비밀도 사람마다 달라야 한다. 고정값을 쓰면
  # 저장소를 읽은 사람 누구나 /api/internal/** 로 공격 로그를 밀어넣을 수 있다.
  itoken=$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
  tmp=$(mktemp)
  sed -e "s|^JWT_SECRET=.*|JWT_SECRET=${secret}|" \
      -e "s|^INTERNAL_SERVICE_TOKEN=.*|INTERNAL_SERVICE_TOKEN=${itoken}|" .env > "$tmp" && mv "$tmp" .env
  ok ".env 생성 + JWT 서명 키 · 내부 서비스 토큰 발급"
fi

# compose 가 파일 단위로 마운트하는 경로는 미리 있어야 한다.
# 없으면 Docker 가 같은 이름의 디렉토리를 만들어 버린다.
mkdir -p tpotce/data/ml-classifier/models tpotce/data/threat-console
[ -f tpotce/data/ml-classifier/models/active-metrics.json ] \
  || die "tpotce/data/ml-classifier/models/active-metrics.json 이 없습니다. 저장소를 다시 받으세요."
ok "마운트 경로 확인"

# 학습된 모델은 저장소에 없다(.gitignore: data/ml-classifier/models/*).
# 없으면 분류기가 규칙만으로 돌면서 조용히 넘어가는데, 지표 파일은 추적되므로
# **화면은 "LightGBM 99.9%" 라고 말한다.** 없는 모델을 있다고 하는 셈이라
# 여기서 먼저 알린다.
if [ -f tpotce/data/ml-classifier/models/multi_model.pkl ]; then
  ok "교차검증 모델 확인"
else
  warn "교차검증 모델(multi_model.pkl)이 없습니다 — 분류는 규칙만으로 동작합니다."
  say "${C_DIM}  대시보드 모델 카드는 지표 파일을 읽으므로 모델이 있는 것처럼 보입니다.${C_OFF}"
  say "${C_DIM}  모델을 받으려면 배포자에게 tpotce/data/ml-classifier/models/ 를 요청하세요.${C_OFF}"
fi

# 시연 데이터 주입 스크립트의 위치는 배치에 따라 다르다.
#   · 개발 트리: capstone-dev 의 **바깥**(../integration-tests)
#   · 공개 저장소: 저장소 루트의 옆(./integration-tests)
# 한쪽만 보면 다른 배치에서 6단계가 조용히 건너뛰어진다 — 스크립트가 없는 것과
# 데이터를 안 넣기로 한 것이 구분되지 않는다.
if [ -d ./integration-tests ]; then
  TESTS_DIR=./integration-tests
elif [ -d ../integration-tests ]; then
  TESTS_DIR=../integration-tests
else
  TESTS_DIR=""
  warn "integration-tests 를 찾지 못했습니다 — 6단계 시연 데이터 주입을 건너뜁니다."
fi

# ─────────────────────────────────────────────────────────────────────────────
head_ "3. 이미지 빌드 (처음이면 5~15분)"
docker compose build 2>&1 | grep -E "Building|Built|ERROR|error" | sed 's/^/  /' || true
ok "빌드 완료"

# ─────────────────────────────────────────────────────────────────────────────
head_ "4. 스택 기동"
docker compose up -d 2>&1 | tail -3 | sed 's/^/  /'

say "${C_DIM}Elasticsearch 준비 대기…${C_OFF}"
for i in $(seq 1 60); do
  st=$(curl -sS -m 3 http://127.0.0.1:19300/_cluster/health 2>/dev/null \
       | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p' || true)
  if [ -n "$st" ]; then ok "Elasticsearch $st"; break; fi
  sleep 3
  [ "$i" = "60" ] && die "Elasticsearch 가 3분 안에 뜨지 않았습니다. docker compose logs elasticsearch 를 확인하세요."
done

say "${C_DIM}백엔드 기동 대기…${C_OFF}"
for i in $(seq 1 40); do
  code=$(curl -sS -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8091/api/health 2>/dev/null || echo 000)
  if [ "$code" = "200" ]; then ok "백엔드 응답"; break; fi
  sleep 3
  [ "$i" = "40" ] && warn "백엔드가 아직 응답하지 않습니다. docker compose logs backend 를 확인하세요."
done

# ─────────────────────────────────────────────────────────────────────────────
head_ "5. LLM 모델"

# 태그의 파라미터 수에서 내려받기 크기를 어림한다. ollama 기본 양자화(Q4)가
# 1B 당 약 0.6GB 다 — exaone3.5:7.8b 4.8GB, qwen2.5:3b 1.9GB 로 실측과 맞는다.
# 태그에서 못 읽으면 크기를 아예 말하지 않는다(틀린 숫자보다 낫다).
model_size_hint() {
  local params
  params=$(printf '%s' "${1#*:}" | grep -oE '^[0-9]+(\.[0-9]+)?[bB]' | tr -dc '0-9.') || return 1
  [ -n "$params" ] || return 1
  awk -v p="$params" 'BEGIN{ printf "%.1f", p * 0.6 }'
}

model=$(grep -E '^LLM_MODEL=' .env | cut -d= -f2- || true)
model=${model:-qwen2.5:3b}

# 이름+태그를 정확히 맞춘다. 예전엔 태그를 떼고(${model%%:*}) 부분 일치로 봤는데,
# 그러면 qwen2.5:7b 가 있을 때 qwen2.5:3b 도 "준비됨" 으로 통과한다.
if docker exec dev-ollama ollama list 2>/dev/null | awk '{print $1}' | grep -Fxq "$model"; then
  ok "${model} 준비됨"
else
  size_hint=$(model_size_hint "$model" || true)
  if [ -n "${size_hint:-}" ]; then
    say "${C_DIM}${model} 내려받는 중(약 ${size_hint}GB, 몇 분 걸립니다)…${C_OFF}"
  else
    say "${C_DIM}${model} 내려받는 중(몇 분 걸립니다)…${C_OFF}"
  fi
  if docker exec dev-ollama ollama pull "$model" 2>&1 | tail -1 | sed 's/^/  /'; then
    actual=$(docker exec dev-ollama ollama list 2>/dev/null \
             | awk -v m="$model" '$1 == m { print $3 " " $4 }' || true)
    ok "${model} 준비됨${actual:+ (${actual})}"
  else
    warn "모델 다운로드 실패 — 나중에 'docker exec dev-ollama ollama pull ${model}' 로 다시 시도하세요."
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
if [ "$SEED" = "1" ] && [ -n "$TESTS_DIR" ]; then
  head_ "6. 시연 데이터"
  if command -v python3 >/dev/null 2>&1; then
    # 주입 전 건수를 먼저 기억한다. 예전엔 ml-analysis-* 전체가 60건 이상인지만
    # 봤는데, 그러면 이미 데이터가 쌓인 스택에서는 주입분이 분류되기도 전에
    # 즉시 통과한다("1028698건 분류됨"). 검증이 아니라 통과 선언이었다.
    seed_count=80
    before=$(curl -sS -m 3 "http://127.0.0.1:19300/ml-analysis-*/_count" 2>/dev/null \
             | sed -n 's/.*"count":\([0-9]*\).*/\1/p' || echo 0)
    before=${before:-0}
    python3 "$TESTS_DIR/inject_sample_docs.py" --host http://127.0.0.1:19300 --count "$seed_count" 2>&1 | sed 's/^/  /'
    say "${C_DIM}분류 대기…${C_OFF}"
    # 분류기는 POLL_INTERVAL(기본 30초) 주기라 2분이면 넉넉하다.
    target=$(( before + seed_count ))
    classified=0
    for i in $(seq 1 24); do
      n=$(curl -sS -m 3 "http://127.0.0.1:19300/ml-analysis-*/_count" 2>/dev/null \
          | sed -n 's/.*"count":\([0-9]*\).*/\1/p' || echo 0)
      n=${n:-0}
      if [ "$n" -ge "$target" ]; then classified=1; ok "주입 ${seed_count}건 분류 완료 (${before} → ${n})"; break; fi
      sleep 5
    done
    [ "$classified" = "1" ] || warn "2분 안에 주입분이 다 분류되지 않았습니다 (${before} → ${n:-?}, 기대 ${target}). docker compose logs ml-classifier 를 확인하세요."
    curl -sS -m 10 -X POST http://127.0.0.1:8091/api/users/signup \
      -H 'Content-Type: application/json' \
      -d '{"email":"demo@jsp.test","password":"demo1234","name":"시연"}' >/dev/null 2>&1 || true
    ok "시연 계정 준비 (demo@jsp.test / demo1234)"
  else
    warn "python3 가 없어 데이터 주입을 건너뜁니다."
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
head_ "준비 완료"
cat <<'EOF'
  대시보드       http://localhost:8002        (demo@jsp.test / demo1234)
  어택맵         http://localhost:8002/tpot-map/
  백엔드 API     http://localhost:8091
  Elasticsearch  http://localhost:19300

  실시간 공격 아크를 보려면 별도 터미널에서:
    python3 "$TESTS_DIR/demo_feed.py" --host http://127.0.0.1:19300

  스택 내리기:  docker compose down
  로그 보기  :  docker compose logs -f <서비스명>
EOF
