# 허니팟 기반 사이버 공격 분석 시스템

정사평 · 캡스톤 디자인 졸업작품

허니팟이 수집한 영문 보안 로그를 **규칙 기반 분류 → 한국어 LLM 해설 → 대시보드**로
자동 변환하는 파이프라인입니다. T-Pot 본체는 수정하지 않고 사이드카로 얹습니다.

공격자를 유인해 기록하는 것까지는 오픈소스가 해줍니다. 남는 것은 **해석**입니다.
T-Pot 은 허니팟 25종의 로그를 쌓아주지만 남는 건 `cowrie.login.failed` 같은 영문
원시 이벤트뿐이고, 이걸 "무슨 일이 있었고 뭘 해야 하나"로 옮기려면 허니팟별
스키마와 MITRE ATT&CK 를 이미 알아야 합니다. 대부분의 조직에는 그 사람이 없습니다.

### 실측 — 시연 데이터가 아니라 실제 공격

AWS 에 올린 T-Pot 이 10일간(2026-04-27 ~ 05-06) 받은 로그 전량을 색인해
파이프라인을 처음부터 끝까지 완주시킨 결과입니다.

| 지표 | 값 | |
|---|---:|---|
| 수집 이벤트 | **1,026,903** | 수집 지점 18종 |
| 고유 공격 IP | **24,346** | 미국 · 브라질 · 영국 순 |
| 고위험 선별 | **45,075** | 전체의 4.4% |
| 규칙·모델 합의율 | **99.9%** | 불일치 782건은 검토 대상 |

측정해서 알게 된 것 네 가지가 이 프로젝트 결과물의 절반입니다.

- **위험도는 LLM 에게 맡길 일이 아니었다** — 3B 가 고위험 10건을 10건 다 낮게
  매겼고 7.8B 도 2/10 에 그쳤습니다. 점수에서 계산하도록 회수했습니다.
- **같은 이야기를 4만 번 쓰고 있었다** — 고위험 45,075건이 실은 **74개 패턴**이고
  상위 2개가 89.8% 를 덮습니다. 패턴당 한 번만 해설해 호출을 99.84% 줄였습니다
  (31.8일 → 75분).
- **모델 성능이 아니라 측정이 틀렸다** — 평가셋을 학습과 다른 인코더로 만들어
  20만 행 중 6만 행이 엉뚱한 코드로 들어갔습니다 (92.5% → 실제 99.9%).
- **게이트는 최적화가 아니라 성립 조건이다** — 위협점수 70 이상만 통과시키는
  필터가 95.6% 를 막습니다. 없으면 100만 건이 전부 추론으로 들어가 725일입니다.

---

## 빠른 시작

```bash
git clone https://github.com/Donghyun0918/honeypot-threat-analyzer.git
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
python3 ./integration-tests/inject_sample_docs.py --host http://127.0.0.1:19300 --count 80
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
python3 ./integration-tests/demo_feed.py --host http://127.0.0.1:19300
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
다른 Docker 스택이 8002·8091·19300·5434 를 쓰고 있는지 확인하세요.
T-Pot 본체를 같은 장비에서 돌리는 중이라면 메모리도 함께 보세요 —
8GB 이하에서는 두 스택을 동시에 띄울 수 없습니다.

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
.
├── setup.sh                    ← 이걸 실행하세요
├── backup.sh                   Postgres 백업/복원
├── .env.example                설정 템플릿
├── docker-compose.yml          컨테이너 10개
├── backend/honeypot/           Spring Boot — JWT 인증 · ES 조회 API
├── frontend/                   Next.js 15 — 한국어 대시보드 · 어택맵
├── integration-tests/          시연 데이터 주입 · 통합 확인
├── promo-site/                 프로젝트 소개 정적 사이트
├── docs/                       보고서 · 폼보드 · 데이터셋 분석
└── tpotce/
    ├── docker/
    │   ├── ml-classifier/      분류 사이드카 + 학습 파이프라인
    │   ├── llm-analyzer/       한국어 해설 사이드카
    │   └── map-override/       어택맵 타일 패치
    └── data/ml-classifier/models/   학습된 모델(v5)
```

`tpotce/` 아래에는 **이 프로젝트가 만든 사이드카만** 들어 있습니다.
T-Pot 본체는 수정하지 않으므로 싣지 않습니다 — 업스트림
([telekom-security/tpotce](https://github.com/telekom-security/tpotce))를
그대로 쓰면 됩니다.

---

## 저장소에 없는 것

**실제 공격 로그와 학습 데이터셋은 포함하지 않았습니다.**

| 빠진 것 | 크기 | 이유 |
|---|---|---|
| 원본 허니팟 로그 | 약 1.3GB | 실제 공격자 IP·자격증명 시도·SSH 세션 기록이 들어 있는 제3자 데이터입니다 |
| 학습 데이터셋 | 약 2.0GB | 위 로그에서 만드는 중간 산출물이라 재생성할 수 있습니다 |
| `.env` | — | JWT 서명 키 등. `setup.sh` 가 `.env.example` 에서 만들어 줍니다 |

**학습된 모델은 포함되어 있습니다**(`tpotce/data/ml-classifier/models/`, 2.8MB).
원시 로그가 아니라 파생 산출물이고, 없으면 교차검증 칸이 비기 때문입니다.
모델 없이도 분류 자체는 규칙으로 그대로 동작합니다.

데이터 없이도 `./setup.sh` 만으로 스택이 뜨고, 시연 데이터가 자동 주입되어
화면이 채워집니다.

---

## 팀

**정사평** — 이현(팀장) · 김동현 · 홍영재 · 이재민
2026년 4월 ~ 9월 · 캡스톤 디자인 졸업작품

자세한 설계 근거와 실측은 [`docs/보고서.pdf`](docs/보고서.pdf) 에 있습니다.
한 장 요약은 [`docs/폼보드.png`](docs/폼보드.png).
