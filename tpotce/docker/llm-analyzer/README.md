# llm-analyzer

`ml-analysis-*`의 **고위험 이벤트만** 골라 한국어 LLM으로 2차 분석하고, 결과를 `llm-analysis-YYYY.MM.dd`에 적재하는 사이드카.

`ml-classifier`가 "이게 **무엇인지**"를 정하면, 이 모듈은 "그래서 **무슨 의미이고 뭘 해야 하는지**"를 한국어로 설명합니다. ES를 읽고 자기 인덱스만 쓰며, 허니팟·Logstash·Kibana 상태는 건드리지 않습니다.

> **2026-08-25 신규 작성.** 원래 PR #3(`feat/llm-analyzer`)로 존재했으나 소스가 로컬 어디에도 남아있지 않아(포크 브랜치에만 존재, 접근 불가) 소비자 측 필드 계약에 맞춰 새로 구현했습니다.

## 파이프라인에서의 위치

```
허니팟 → logstash-*  →  ml-classifier  →  ml-analysis-*  →  llm-analyzer  →  llm-analysis-*
                                              (분류)                (해설)         ↓
                                                                    threat-console / Spring backend / Next.js
```

## 출력 필드 계약

`llm-analysis-*`를 읽는 세 소비자(threat-console `/api/llm-recent`·`/api/llm-stats`, Spring `ThreatConsoleService.llmRecent/llmStats`, Next.js `/api/attacks?view=llm`)가 기대하는 필드와 정확히 일치합니다.

| 필드 | 타입 | 설명 |
|---|---|---|
| `summary_ko` | text | 비전문가도 이해 가능한 1~3문장 한국어 요약 |
| `solution_ko` | text | 즉시 실행 가능한 대응 조치 |
| `severity` | **keyword** | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `risk_score` | float | 0~10 (범위 밖 값은 클램프) |
| `ttp_inferred` | keyword[] | MITRE 기법 ID 배열. `T1110`, `T1059.004` 형식만 통과 |
| `llm_status` | keyword | `ok` \| `fallback` |
| `llm_provider` / `llm_model` | keyword | 어떤 모델이 만든 결과인지 추적용 |

원본 문서에서 `src_ip`, `dest_port`, `honeypot`, `ml_label`, `mitre_score`, `mitre_technique`를 함께 복사해 조인 없이 조회 가능합니다.

### ⚠️ 인덱스 템플릿이 필수인 이유

소비자들은 `severity`를 **서브필드 없이** 집계합니다(`terms(field="severity")`). ES 동적 매핑에 맡기면 `severity`가 `text`가 되어 이 집계가 `Fielddata is disabled`로 **실패**하는데, threat-console과 Spring 모두 이 예외를 catch해 **빈 차트로 삼켜버립니다**(조용한 실패). 그래서 데몬은 기동 시 `llm-analysis` 인덱스 템플릿을 먼저 등록해 `severity`를 `keyword`로 고정합니다.

`honeypot`은 반대로 `honeypot.keyword`로 집계되므로 기본 text+keyword 형태를 유지합니다.

## 환경 변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `ES_HOST` | `http://elasticsearch:9200` | Elasticsearch 주소 |
| `ES_SOURCE_INDEX` | `ml-analysis-*` | 입력 인덱스 패턴 |
| `ES_TARGET_PREFIX` | `llm-analysis-` | 출력 인덱스 접두사 |
| `MIN_SCORE` | `70` | 이 `mitre_score` 이상만 분석 (LLM 비용 게이트) |
| `POLL_INTERVAL_SEC` | `120` | 폴링 주기 |
| `BATCH_SIZE` | `20` | 1회 주기당 최대 분석 건수 |
| `BOOTSTRAP_WINDOW` | `now-24h` | 커서 없을 때 최초 조회 범위 |
| `STATE_DIR` | `/data/llm-analyzer` | 커서 저장 경로 |
| `LLM_PROVIDER` | `ollama` | `ollama` \| `openai` \| `anthropic` \| `gemini` |
| `LLM_MODEL` | 제공자별 기본값 | 모델명 |
| `OLLAMA_HOST` | `http://ollama:11434` | Ollama 주소 |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | – | 외부 제공자 키 |
| `LLM_TIMEOUT_SEC` | `120` | 제공자 호출 타임아웃 |
| `LLM_MAX_RETRIES` | `2` | 문서당 재시도 횟수 (소진 시 폴백) |
| `WRITE_FALLBACK` | `true` | `false`면 폴백 문서를 적재하지 않고 건너뜀 |

제공자 환경변수는 프론트엔드 `src/lib/llm-providers.ts`와 **동일한 이름**을 씁니다. `.env` 하나로 사이드카와 UI가 같은 백엔드를 바라봅니다.

## 비용·안정성 설계

- **게이트**: `mitre_score >= MIN_SCORE`인 문서만 호출 대상. LightGBM 추론과 달리 LLM 호출은 초 단위이므로 배치를 작게(기본 20건/주기) 잡습니다.
- **중복 과금 방지**: 배치를 분석하기 **전에** 대상 인덱스에서 기존 `_id`를 조회해 걸러냅니다. `create` op-type도 중복 쓰기를 막지만 그건 LLM 호출 **후**라, 커서가 유실되면(state 볼륨 초기화 등) 부트스트랩 구간 전체가 재과금됩니다.
- **폴백**: 제공자가 죽었거나 응답이 파싱 불가면 `mitre_score` 기반 결정론적 요약을 쓰고 `llm_status=fallback` + `llm_fallback_reason`을 남깁니다. 문서가 조용히 사라지지 않고, 운영자가 필터로 걸러낼 수 있습니다.
- **커서**: `(@timestamp, _seq_no)` 복합 키 `search_after`. 같은 밀리초 문서가 누락/무한재처리되지 않습니다. SIGTERM 시 배치 중간에서 멈추고 처리한 만큼만 커서를 전진시킵니다.

## 실행

T-Pot 위에 얹기 (`sidecars_overlay.yml`):

```bash
docker compose -f docker-compose.yml -f compose/sidecars_overlay.yml \
    up -d --build llm-analyzer
```

졸작 스택 (`capstone/docker-compose.yml`)에서는 `capstone-llm-analyzer`로 기동하며 `capstone-ollama`를 사용합니다.

```bash
cd /mnt/d/integration/T-POT_PR/capstone && docker compose up -d llm-analyzer
```

## 검증 방법

```bash
# 적재 확인
curl -s "$ES/llm-analysis-*/_search?size=1&pretty"

# severity 매핑이 keyword 인지 (text 면 집계가 조용히 실패)
curl -s "$ES/llm-analysis-*/_mapping/field/severity"

# 소비자가 실제로 쓰는 집계
curl -s -H 'Content-Type: application/json' "$ES/llm-analysis-*/_search" -d '{
  "size":0,"aggs":{"severity":{"terms":{"field":"severity","size":4}}}}'

# 폴백 비율 (높으면 제공자 문제)
curl -s -H 'Content-Type: application/json' "$ES/llm-analysis-*/_search" -d '{
  "size":0,"aggs":{"s":{"terms":{"field":"llm_status"}}}}'
```
