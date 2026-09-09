#!/usr/bin/env bash
# T-Pot local setup for WSL2
# 데이터는 WSL2 네이티브 ext4(~/tpotce)에 저장 — NTFS(/mnt/d) 사용 시 chattr/권한 이슈 발생
set -euo pipefail

TPOT_SRC="$(cd "$(dirname "$0")" && pwd)"   # 소스코드 위치 (현재 디렉토리)
TPOT_HOME="$HOME/tpotce"                      # 데이터 위치 (WSL2 ext4)

echo "=== T-Pot WSL2 로컬 설정 ==="
echo "소스: $TPOT_SRC"
echo "데이터: $TPOT_HOME"
echo ""

# ── 1. 데이터 디렉토리 (WSL2 native ext4) ────────────────────────────────────
mkdir -p "$TPOT_HOME/data"

# ── 2. .env 생성 ─────────────────────────────────────────────────────────────
ENV_FILE="$TPOT_SRC/.env"
if [ -f "$ENV_FILE" ]; then
    echo "[SKIP] .env 이미 존재: $ENV_FILE"
else
    echo "[INFO] .env 생성 중..."

    # WEB_USER 생성 (기본 admin/admin — 로컬 개발용)
    if command -v htpasswd &>/dev/null; then
        WEB_USER_B64=$(htpasswd -n -b "admin" "admin" 2>/dev/null | base64 -w0)
    else
        # htpasswd 없으면 미리 생성된 admin:admin 해시 사용
        WEB_USER_B64="YWRtaW46JGFwcjEkWFJxNkgua24kVUY2UDNVVUJiVTViVEJjZkhkblBUMQo="
    fi

    cat > "$ENV_FILE" << EOF
# T-Pot local WSL2 config
WEB_USER=${WEB_USER_B64}
LS_WEB_USER=
TPOT_BLACKHOLE=DISABLED
TPOT_PERSISTENCE=on
TPOT_PERSISTENCE_CYCLES=30
TPOT_TYPE=HIVE
TPOT_HIVE_USER=
LS_SSL_VERIFICATION=full
TPOT_HIVE_IP=
TPOT_ATTACKMAP_TEXT=ENABLED
TPOT_ATTACKMAP_TEXT_TIMEZONE=UTC
OINKCODE=OPEN
BEELZEBUB_LLM_MODEL=ollama
BEELZEBUB_LLM_HOST=http://ollama.local:11434/api/chat
BEELZEBUB_OLLAMA_MODEL=openchat
GALAH_LLM_PROVIDER=ollama
GALAH_LLM_SERVER_URL=http://ollama.local:11434
GALAH_LLM_MODEL=llama3.1
TPOT_DOCKER_SOCK=/var/run/docker.sock
TPOT_DOCKER_ENV=./.env
TPOT_DOCKER_COMPOSE=./docker-compose.yml
TPOT_REPO=ghcr.io/telekom-security
TPOT_VERSION=24.04.1
TPOT_PULL_POLICY=missing
TPOT_DATA_PATH=${TPOT_HOME}/data
TPOT_OSTYPE=linux
EOF
    echo "[OK] .env 생성 완료 (admin/admin)"
fi

# ── 3. sidecars_overlay.yml 경로 확인 ────────────────────────────────────────
OVERLAY="$TPOT_SRC/compose/sidecars_overlay.yml"
if [ ! -f "$OVERLAY" ]; then
    echo "[ERROR] $OVERLAY 없음"
    exit 1
fi

# ── 4. 안내 출력 ─────────────────────────────────────────────────────────────
WSL_IP=$(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)

echo ""
echo "=== 설정 완료 ==="
echo ""
echo "▶ 실행 (전체 T-Pot + 사이드카):"
echo ""
echo "   cd $TPOT_SRC"
echo "   docker compose up -d"
echo "   # 우리 사이드카 추가:"
echo "   docker compose -f docker-compose.yml -f compose/sidecars_overlay.yml up -d --build threat-console ml-classifier"
echo ""
echo "▶ 접속 주소:"
echo "   T-Pot 웹UI    : https://${WSL_IP}:64297  (admin / admin)"
echo "   Kibana        : https://${WSL_IP}:64297/kibana"
echo "   threat-console: https://${WSL_IP}:64297/threat-console/"
echo "   Elasticsearch : http://localhost:64298"
echo ""
echo "▶ Windows 브라우저에서 접속하려면:"
echo "   WSL2 IP = ${WSL_IP}"
echo "   또는 PowerShell(관리자)에서:"
echo "   netsh interface portproxy add v4tov4 listenport=64297 listenaddress=0.0.0.0 connectport=64297 connectaddress=${WSL_IP}"
echo ""
echo "▶ 메모리 부족 시 ~/.wslconfig 에 추가:"
echo "   [wsl2]"
echo "   memory=10GB"
echo "   processors=8"
echo ""
echo "▶ 이미지 풀 예상 시간: 첫 실행 15~30분 (약 8GB)"
