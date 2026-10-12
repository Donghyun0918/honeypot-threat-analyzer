# 허니팟 기반 사이버 공격 분석 시스템

정사평 · 캡스톤 디자인 졸업작품

허니팟이 수집한 영문 보안 로그를 **규칙 기반 분류 → 한국어 LLM 해설 → 대시보드**로
자동 변환하는 파이프라인입니다. T-Pot 본체는 수정하지 않고 사이드카로 얹습니다.

---

## 빠른 시작

```bash
git clone <저장소>
cd T-POT_PR/capstone-dev
./setup.sh
```

끝입니다. 스크립트가 환경 점검 → `.env` 생성 → 이미지 빌드 → 기동 →
LLM 모델 다운로드 → 시연 데이터 주입까지 합니다. 여러 번 실행해도 안전합니다.

| | 주소 |
|---|---|
| **대시보드** | http://localhost:8002 |
| 어택맵 | http://localhost:8002/tpot-map/ |
| 백엔드 API | http://localhost:8091 |
| Elasticsearch | http://localhost:19300 |

**시연 계정** `demo@jsp.test` / `demo1234`
(로그인 화면의 "시연 계정으로 로그인" 버튼을 누르면 자동으로 채워집니다.)

### 옵션

```bash
./setup.sh --check     # 환경만 점검하고 종료 (설치 전에 확인용)
./setup.sh --no-seed   # 데이터 주입 없이 기동만
```

---

## 필요한 것

| 항목 | 최소 | 비고 |
|---|---|---|
| Docker Desktop | v2 compose 포함 | 실행 중이어야 합니다 |
| 메모리 | **6GB 이상** | Elasticsearch + Ollama 를 같이 띄웁니다 |
| 디스크 | **12GB** | 이미지 약 6GB + LLM 모델 2~5GB (`.env` 의 `LLM_MODEL` 에 따라 — 기본 `qwen2.5:3b` 1.9GB, `exaone3.5:7.8b` 4.8GB) |
| python3 | 선택 | 시연 데이터 주입에만 씁니다 |

첫 실행은 이미지 빌드와 모델 다운로드 때문에 **10~20분** 걸립니다.
두 번째부터는 1분 안에 뜹니다.

---

## 무엇이 도는가

```
허니팟 로그 ─► logstash-*  ─►  ml-classifier  ─►  ml-analysis-*
                              (규칙 기반 분류)         │
                                                       │ mitre_score ≥ 70 만
                                                       ▼
                              llm-analyzer  ─────►  llm-analysis-*
                              (한국어 요약·대응)         │
                                                       ▼
                          Spring 백엔드 ─► Next.js 대시보드 · 어택맵
```

컨테이너 10개가 뜹니다.

| 컨테이너 | 역할 |
|---|---|
| `dev-es` | Elasticsearch — 로그 저장·집계 |
| `dev-postgres` | 사용자·프로젝트·공격로그 |
| `dev-backend` | Spring Boot — JWT 인증 + ES 조회 |
| `dev-frontend` | Next.js — 한국어 대시보드 |
| `dev-ml-classifier` | 30초 주기 분류 |
| `dev-llm-analyzer` | 60초 주기 한국어 해설 |
| `dev-ollama` | 로컬 LLM 추론 |
| `dev-map_web` / `map_data` / `map_redis` | 실시간 공격 지도 |

---

## 자주 겪는 문제

**대시보드에 아무것도 안 보입니다**
개요는 기본값이 **최근 24시간**(통계는 7일)입니다. 원인이 둘 중 하나입니다.

*데이터가 없다* — 시연 데이터를 다시 넣으세요:
```bash
python3 ../integration-tests/inject_sample_docs.py --host http://127.0.0.1:19300 --count 80
```

*데이터는 있는데 오래됐다* — **보관된 로그를 적재했다면 데이터가 몇 달 전이라
24시간 창에 하나도 안 걸립니다.** 화면이 전부 0 으로 보이는 게 이 경우입니다.
`.env` 에서 집계 창을 늘리고 재기동하세요:
```bash
THREAT_CONSOLE_WINDOW_SHORT=now-1y
THREAT_CONSOLE_WINDOW_LONG=now-1y
```
분류기도 마찬가지입니다 — `ML_BOOTSTRAP_WINDOW` 가 `now-24h` 면 오래된 문서를
아예 읽지 않습니다.

**어택맵이 비어 있습니다**
지도는 **실시간으로 들어오는** 이벤트만 그립니다(최근 약 10초 창).
한 번 주입한 데이터로는 아크가 생기지 않습니다. 별도 터미널에서:
```bash
python3 ../integration-tests/demo_feed.py --host http://127.0.0.1:19300
```
Ctrl-C 로 멈춥니다. 시연 영상을 찍을 때도 이걸 켜두세요.

**"LLM 분석 완료"가 0이거나 잘 안 늘어납니다**
CPU 추론이라 느립니다 — `exaone3.5:7.8b` 실측 **건당 약 60초**(1분에 10건
배치 하나), 기본값인 3B 는 약 27초입니다. 고위험이 수백 건이면
따라잡는 데 시간이 걸립니다. 급하면 `.env` 에서 `LLM_MIN_SCORE` 를 올려
대상을 줄이세요.

**로그인이 안 됩니다**
`./setup.sh` 를 `--no-seed` 로 돌렸다면 시연 계정이 없습니다. 회원가입하거나:
```bash
curl -X POST http://localhost:8091/api/users/signup -H 'Content-Type: application/json' \
  -d '{"email":"demo@jsp.test","password":"demo1234","name":"시연"}'
```

**재기동했더니 로그인이 풀립니다**
`.env` 의 `JWT_SECRET` 이 비어 있으면 기동할 때마다 임의 키가 생성됩니다.
`./setup.sh` 가 채워주지만, 직접 만들려면 `openssl rand -base64 48`.

**포트가 이미 쓰이고 있다고 합니다**
다른 스택(`../capstone`)이 떠 있을 수 있습니다. `cd ../capstone && docker compose down`.
메모리가 8GB 이하면 **두 스택을 동시에 띄울 수 없습니다.**

**메모리가 부족해 보입니다**
`docker stats` 로 확인하세요. Ollama 가 모델을 상주시켜 2~3GB 를 씁니다.
LLM 이 필요 없으면 `docker compose stop llm-analyzer ollama`.

---

## 테스트

준비물 없이 돕니다(표준 라이브러리만 씁니다 — pytest 를 깔아야 하면 아무도 안 돌립니다).

```bash
python3 tpotce/docker/ml-classifier/tests/run.py   # 규칙 라벨러 · 특징 추출
python3 tpotce/docker/llm-analyzer/tests/run.py    # 한국어 해설 파싱

# 프론트 LLM 경로(대시보드 온디맨드 분석)의 한자 차단 · 폴백
docker run --rm -v "$PWD/frontend:/w" -w /w node:20-alpine node --test tests/

# 백엔드 — 예외 매핑 · 자산 목록 격리 · 내부 엔드포인트 인증/검증
docker run --rm -v "$PWD/backend/honeypot:/app" -w /app \
  -v gradle-cache:/root/.gradle gradle:8.10-jdk17 gradle test --no-daemon
```

백엔드 테스트도 **DB·ES 없이 돕니다.** 전체 컨텍스트를 올려야 하는 기본
`contextLoads` 만 비활성이고(스택을 띄운 상태라면 `@Disabled` 를 지우면 됩니다),
나머지는 리포지토리를 인터페이스 그대로 흉내 내 검증합니다.

이 테스트는 "함수가 도는가"를 보지 않습니다. **실제로 겪은 조용한 실패를 하나씩
못 박아 둔 것**이라, 각 테스트에 그 실패가 무엇이었는지 적혀 있습니다.
`int("23.0")` 이 포트를 0 으로 만들던 것, suricata `payload` 를 안 읽던 것,
경보 없는 행을 전부 정찰로 부르던 것, LLM 이 고위험 문서에 `LOW` 를 반환하던 것 등.

분류 규칙이나 프롬프트 파싱을 건드리면 **고치기 전에 여기부터 돌리세요.**

---

## 알아둘 것

**분류는 규칙이 기준선이고, 모델은 교차검증만 합니다.** 모델은 라벨을 뒤집지
못하고 자기 판단을 `ml_label_raw` 에 남깁니다. 실제 공격 로그 **1,026,903건
전량에서 합의 99.9%**, 불일치 782건은 검토 대상으로 표시됩니다.

불일치 782건 중 707건이 **Suricata** 이고 방향도 한쪽입니다 — 규칙이
Malware(414)·Intrusion(194) 이라 한 것을 모델이 Recon 으로 낮춰 봅니다.
교차검증의 값어치는 합의율 자체가 아니라, 이 782건이 **사람이 볼 큐로
떠오른다**는 데 있습니다.

> 2026-09-15 에 교차검증 모델을 v4(CSV 세션조인 학습) → **v5(실 ES 문서
> 25만행 학습)** 로 교체했습니다. v4 때는 같은 데이터에서 합의 87.6%(불일치
> 126,756건)였는데 그 대부분이 모델 쪽 오답이었습니다 — Recon 392,668건 중
> 107,257건, Brute Force 23,061건 중 18,593건을 다르게 봤습니다. 검토 큐가
> 모델 오답으로 채워지던 상태였습니다.
>
> 그전 시연 표본(1,736건)에서는 합의 81.5% · 불일치 322건이었고, 전부 Cowrie
> 의 같은 오답(규칙 Intrusion, 모델 Malware)이었습니다. 학습셋에 cowrie
> Intrusion 이 0건이라 모델이 본 적 없는 유형이었고, 그 322건의 모델 확신도가
> 평균 98.9% 여서 **확신도 임계값으로는 거를 수 없었습니다.**

자세한 근거는 `tpotce/docker/ml-classifier/training/DATASET_FINDINGS.md` §6.

**위험도(severity)는 점수에서 계산합니다.** LLM 에게는 한국어 문장만 맡깁니다.
3B 가 고위험 10건 중 10건을 낮게 매겼고, **7B 로 올려도 2/10 에 그쳤습니다** —
모델 크기 문제가 아니라 애초에 맡길 일이 아니었습니다. `.env` 의 `LLM_SEVERITY=model`
로 되돌릴 수 있지만, 그때도 **점수보다 낮게 잡는 것은 막습니다**(올려잡는 것만 수용).

**어택맵 타일은 OpenStreetMap 입니다.** CARTO 가 API 키를 요구하도록 바뀌면서
타일마다 "API KEY REQUIRED" 워터마크가 찍혀 교체했습니다
(`tpotce/docker/map-override/map.js`).

---

## 디렉토리

```
capstone-dev/
├── setup.sh                    ← 이걸 실행하세요
├── .env.example                설정 템플릿
├── docker-compose.yml          컨테이너 10개
├── backend/honeypot/           Spring Boot
├── frontend/                   Next.js
└── tpotce/
    ├── docker/
    │   ├── ml-classifier/      분류 사이드카 + 학습 파이프라인
    │   ├── llm-analyzer/       한국어 해설 사이드카
    │   ├── threat-console/     순정 T-Pot 용 Flask 콘솔
    │   └── map-override/       어택맵 타일 패치
    ├── compose/                T-Pot 프로파일
    └── data/                   학습 데이터 (저장소에 없음, 재생성 가능)
```

`../capstone/` 은 개선 전 원본입니다. 비교·복구용으로만 두고 개발은 여기서 합니다.
