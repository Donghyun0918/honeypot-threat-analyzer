# threat-console

Korean unified web UI that consolidates `ml-classifier` and `llm-analyzer`
output into a single console with built-in Korean PDF report generation.

> **Opt-in.** Use `compose/threat_intel.yml` instead of `compose/ml_llm.yml`
> to include this container.

## What it does

Single-page application served at `https://<tpot-host>:64297/threat-console/`
with four tabs:

| Tab            | Contents                                                        |
|----------------|-----------------------------------------------------------------|
| **개요**       | 24h overview cards (total events / classified attacks / high-risk / LLM analyzed) + timeline + score histogram |
| **ML 분류**    | Attack-type doughnut + per-honeypot bar from `ml-analysis-*`    |
| **LLM 분석**   | Severity / risk-score charts + filterable table of recent Korean summaries |
| **리포트**     | Date range picker → generate Korean PDF report on demand        |

The console talks to Elasticsearch read-only — it does not modify
indices or saved objects.

## Architecture

```
        ┌─────────────────┐
        │ /threat-console │ ← nginx (TPot port 64297, basic auth)
        └────────┬────────┘
                 │ proxy_pass
                 ▼
        ┌─────────────────┐
        │  Flask (gunicorn)│
        │   port 8080     │
        └────────┬────────┘
                 │ ES queries
                 ▼
        ┌─────────────────┐
        │  Elasticsearch  │
        │   logstash-*    │
        │   ml-analysis-* │
        │   llm-analysis-*│
        └─────────────────┘
```

PDF generation is done in-process with WeasyPrint using the bundled
Noto CJK Korean font.

## Endpoints

| Method | Path                                | Purpose                          |
|--------|-------------------------------------|----------------------------------|
| GET    | `/`                                 | SPA shell                        |
| GET    | `/api/overview`                     | 24h totals (4 cards)             |
| GET    | `/api/ml-stats?since=now-24h`       | ML aggregations                  |
| GET    | `/api/llm-stats?since=now-7d`       | LLM severity/risk aggregations   |
| GET    | `/api/llm-recent?since=&severity=`  | Table data                       |
| POST   | `/api/report`  body: `{since}`      | Generate PDF, returns `report_id`|
| GET    | `/api/report/<id>`                  | Download PDF                     |
| GET    | `/api/reports`                      | List recent PDFs                 |
| GET    | `/api/health`                       | Health check                     |

## Configuration

| Variable      | Default                                | Description           |
|---------------|----------------------------------------|-----------------------|
| `ES_HOST`     | `http://elasticsearch:9200`            | Elasticsearch URL     |
| `REPORT_DIR`  | `/data/threat-console/reports`         | Persisted PDF storage |
| `LISTEN_PORT` | `8080`                                 | HTTP listen port      |

## How to enable

```bash
cp compose/threat_intel.yml docker-compose.yml

# .env: LLM provider (required for LLM tab to populate)
echo "LLM_ANALYZER_PROVIDER=ollama"           >> .env
echo "LLM_ANALYZER_SERVER_URL=http://host.docker.internal:11434" >> .env
echo "LLM_ANALYZER_MODEL=llama3.1:8b"         >> .env

docker compose up -d
```

Open `https://<tpot-host>:64297/` and click **Threat Console** on the
landing page (or go directly to `/threat-console/`).

## PDF report contents

1. **종합 요약** — 4 stat boxes (events, attacks, high-risk, LLM analyzed)
2. **공격 유형 분포** — table from `ml-analysis-*` (Recon / Brute Force / Malware / Intrusion / Etc)
3. **허니팟별 공격 통계** — top honeypots by attack count
4. **심각도별 LLM 분석 분포** — LOW / MEDIUM / HIGH / CRITICAL
5. **고위험 사건 상세** — top-50 HIGH/CRITICAL events with Korean
   summary, mitigation, and inferred MITRE techniques

PDF is rendered with WeasyPrint using the bundled Noto CJK font, so
Korean text is reliable across all PDF readers.
