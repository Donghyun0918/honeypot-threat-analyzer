#!/bin/sh
# Postgres 백업 — 계정·프로젝트·자산 목록.
#
# **왜 이것만 백업하는가.** 이 스택에서 다시 만들 수 없는 것은 두 가지다:
#   · 원본 허니팟 로그  → T-POT_PR/logs/ 에 있고 드라이브 보관본에도 들어간다
#   · Postgres 의 계정과 자산 목록  → 볼륨에만 있다.  ← 이 스크립트가 맡는다
# Elasticsearch 는 로그에서 다시 색인·분류하면 되므로 백업하지 않는다
# (그 절차는 작업 로그 §8-3·§16).
#
# **왜 필요한가.** `docker compose down -v` 한 번이면 계정이 전부 사라진다.
# 실제로 한 번 했었고(§8), 그때는 계정이 몇 개 없어서 넘어갔다. 시연 직전에
# 같은 일이 나면 demo 계정도, 팀원들이 넣어둔 자산 목록도 없다.
#
#   ./backup.sh              백업 만들기
#   ./backup.sh --list       가진 백업 보기
#   ./backup.sh --restore <파일>   되돌리기 (덮어쓴다, 확인을 묻는다)
set -e
cd "$(dirname "$0")"

DIR=backups
KEEP=10          # 이 개수만 남기고 오래된 것부터 지운다
CONTAINER=dev-postgres
DB=honeypot_db
USER=postgres

die() { printf '%s\n' "$*" >&2; exit 1; }

docker inspect "$CONTAINER" >/dev/null 2>&1 \
  || die "$CONTAINER 가 없습니다. 스택을 먼저 올리세요: ./setup.sh"
[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" = "true" ] \
  || die "$CONTAINER 가 실행 중이 아닙니다: docker compose up -d postgres"

# ── 목록 ──────────────────────────────────────────────────────────────────
if [ "$1" = "--list" ]; then
  [ -d "$DIR" ] || die "백업이 없습니다."
  ls -lh "$DIR" | tail -n +2
  exit 0
fi

# ── 복원 ──────────────────────────────────────────────────────────────────
if [ "$1" = "--restore" ]; then
  SRC="${2:?사용법: ./backup.sh --restore <백업파일>}"
  [ -f "$SRC" ] || die "$SRC 가 없습니다."
  printf '%s\n' "$SRC 로 $DB 를 덮어씁니다. 지금 데이터는 사라집니다."
  printf '계속하려면 yes 를 입력하세요: '
  read -r ans
  [ "$ans" = "yes" ] || die "취소했습니다."
  # pg_dump --clean 으로 떴으므로 기존 객체를 지우고 다시 만든다.
  gunzip -c "$SRC" | docker exec -i "$CONTAINER" psql -U "$USER" -d "$DB" -v ON_ERROR_STOP=1
  printf '%s\n' "복원 완료. 백엔드를 재기동하세요: docker compose restart backend"
  exit 0
fi

# ── 백업 ──────────────────────────────────────────────────────────────────
mkdir -p "$DIR"
OUT="$DIR/honeypot_db_$(date +%Y%m%d-%H%M).sql.gz"

# --clean --if-exists: 복원할 때 기존 객체를 먼저 지운다. 없으면 복원이
# "이미 있다" 오류로 중간에 멈춘다.
docker exec "$CONTAINER" pg_dump -U "$USER" -d "$DB" --clean --if-exists \
  | gzip -9 > "$OUT"

# 덤프가 실제로 내용을 담았는지 본다. pg_dump 가 실패해도 파이프 때문에
# **빈 gz 파일이 생기고 종료코드는 0 이 된다** — 있으나 마나 한 백업이 조용히
# 쌓이는 상태가 제일 나쁘다.
if [ "$(gunzip -c "$OUT" | grep -c 'CREATE TABLE')" -lt 1 ]; then
  rm -f "$OUT"
  die "백업에 테이블이 없습니다. 지웠습니다. docker logs $CONTAINER 를 확인하세요."
fi

ROWS=$(gunzip -c "$OUT" | grep -c '^COPY ' || true)
printf '%s\n' "백업 완료: $OUT ($(du -h "$OUT" | cut -f1), 테이블 데이터 $ROWS 블록)"

# 오래된 것 정리
COUNT=$(ls -1 "$DIR"/honeypot_db_*.sql.gz 2>/dev/null | wc -l)
if [ "$COUNT" -gt "$KEEP" ]; then
  ls -1t "$DIR"/honeypot_db_*.sql.gz | tail -n +$((KEEP + 1)) | while read -r old; do
    rm -f "$old"
    printf '%s\n' "  오래된 백업 삭제: $old"
  done
fi
