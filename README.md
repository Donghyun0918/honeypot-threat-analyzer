# 허니팟 기반 사이버 공격 분석 시스템

정사평 · 캡스톤 디자인 졸업작품

허니팟이 수집한 영문 보안 로그를 **규칙 기반 분류 → 한국어 LLM 해설 → 대시보드**로
자동 변환하는 파이프라인입니다. T-Pot 본체는 수정하지 않고 사이드카로 얹습니다.

---

## 빠른 시작

```bash
git clone https://github.com/<계정>/honeypot-threat-analyzer.git
cd honeypot-threat-analyzer
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
| 디스크 | **12GB** | 이미지 약 6GB + LLM 모델 약 2GB |
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
개요는 최근 24시간만 집계합니다. 데이터를 다시 넣으세요:
```bash
python3 ./integration-tests/inject_sample_docs.py --host http://127.0.0.1:19300 --count 80
```

**어택맵이 비어 있습니다**
지도는 **실시간으로 들어오는** 이벤트만 그립니다(최근 약 10초 창).
한 번 주입한 데이터로는 아크가 생기지 않습니다. 별도 터미널에서:
```bash
python3 ./integration-tests/demo_feed.py --host http://127.0.0.1:19300
```
Ctrl-C 로 멈춥니다. 시연 영상을 찍을 때도 이걸 켜두세요.

**"LLM 분석 완료"가 0이거나 잘 안 늘어납니다**
CPU 추론이라 건당 약 27초, 1분에 10건씩 처리합니다. 고위험이 수백 건이면
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
이미 이 스택이 떠 있을 수 있습니다: `docker compose down` 후 다시 시도하세요.
다른 프로그램이 8002·8091·19300 을 쓰고 있다면 그쪽을 정리해야 합니다.

**메모리가 부족해 보입니다**
`docker stats` 로 확인하세요. Ollama 가 모델을 상주시켜 2~3GB 를 씁니다.
LLM 이 필요 없으면 `docker compose stop llm-analyzer ollama`.

---

## 알아둘 것

**분류는 규칙 기반입니다.** 학습한 LightGBM 모델이 있지만 현재 데이터에서
규칙보다 성능이 낮아(규칙 대비 79%) 꺼져 있습니다. 대시보드의 "현재 분류 모델"
카드가 "규칙 기반"으로 표시되는 것이 정상입니다. 자세한 근거는
`tpotce/docker/ml-classifier/training/DATASET_FINDINGS.md`.

**위험도(severity)는 점수에서 계산합니다.** LLM 에게는 한국어 문장만 맡깁니다.
3B 모델이 위험도 판정을 전혀 못 해서(고위험 10건 중 10건을 낮게 매김) 설계를
바꿨습니다. 더 강한 모델을 쓰면 `.env` 에 `LLM_SEVERITY=model` 로 되돌릴 수 있습니다.

**어택맵 타일은 OpenStreetMap 입니다.** CARTO 가 API 키를 요구하도록 바뀌면서
타일마다 "API KEY REQUIRED" 워터마크가 찍혀 교체했습니다
(`tpotce/docker/map-override/map.js`).

---

## 디렉토리

```
honeypot-threat-analyzer/
├── setup.sh                    ← 이걸 실행하세요
├── .env.example                설정 템플릿
├── docker-compose.yml          컨테이너 10개
├── backend/honeypot/           Spring Boot
├── frontend/                   Next.js
├── integration-tests/          시연 데이터 주입·연속 피드
├── docs/                       보고서 PDF · 폼보드
└── tpotce/
    ├── docker/
    │   ├── ml-classifier/      분류 사이드카 + 학습 파이프라인
    │   ├── llm-analyzer/       한국어 해설 사이드카
    │   ├── threat-console/     순정 T-Pot 용 Flask 콘솔
    │   └── map-override/       어택맵 타일 패치
    ├── compose/                T-Pot 프로파일
    └── data/                   학습 데이터 (저장소에 없음, 재생성 가능)
```

