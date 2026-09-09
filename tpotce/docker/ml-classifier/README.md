# ml-classifier

Sidecar daemon that polls T-Pot's existing `logstash-*` Elasticsearch
indices, classifies each honeypot event as one of five attack types, and
writes the result to `ml-analysis-YYYY.MM.dd` for visualization in Kibana.

This container reads from T-Pot's ELK stack only — it does not modify
Logstash, Kibana, or any honeypot configuration.

## What it adds

| Field             | Description                                            |
|-------------------|--------------------------------------------------------|
| `ml_label`        | One of `Recon`, `Brute Force`, `Malware`, `Intrusion`, `Etc` |
| `ml_is_attack`    | Boolean (derived from `ml_label`: `Etc` → false, else true) |
| `ml_multi_conf`   | 0–100 confidence (rule-based fallback: 100)            |
| `mitre_score`     | 0–100, MITRE ATT&CK threat score                       |
| `mitre_technique` | MITRE technique ID (e.g. `T1110`, `T1046`)             |
| `model_used`      | `rule` or `ml`                                         |
| `model_version`   | e.g. `rule-1.0`                                        |

## How to enable

Use the bundled compose file instead of `standard.yml`:

```bash
cp compose/ml.yml docker-compose.yml
docker compose up -d
```

The `ml-classifier` container starts alongside the standard T-Pot stack
and begins populating `ml-analysis-*` from the most recent honeypot
events. Open Kibana → **Dashboards** → **ML Analysis - Honeypot Attack
Classification**.

## Configuration

All knobs are environment variables on the `ml-classifier` service:

| Variable             | Default                | Description                  |
|----------------------|------------------------|------------------------------|
| `ES_HOST`            | `http://elasticsearch:9200` | ES endpoint              |
| `ES_SOURCE_INDEX`    | `logstash-*`           | Source index pattern         |
| `ES_TARGET_PREFIX`   | `ml-analysis-`         | Target index prefix          |
| `POLL_INTERVAL_SEC`  | `60`                   | Seconds between polls        |
| `BATCH_SIZE`         | `1000`                 | Max docs per poll            |
| `BOOTSTRAP_WINDOW`   | `now-5m`               | First-run lookback window    |
| `MODEL_DIR`          | `/opt/ml-classifier/models` | Holds `multi_model.pkl` + `encoders.json` |

## Pagination correctness

The cursor is a `(timestamp_ms, _seq_no)` compound key persisted to
`/data/ml-classifier/cursor.json`. This avoids the timestamp-tie pitfall
where many honeypot events share the same millisecond and a naive
`gte: last_ts` query would either skip or replay them.

## Rule-based fallback

If no trained `multi_model.pkl` is present in `MODEL_DIR`, the
classifier falls back to deterministic rules in `rule_label.py`. The
rules are calibrated against T-Pot's actual honeypot output (Suricata
alert categories, Cowrie eventids, P0f/Fatt fingerprinting, ConPot
industrial protocols, etc.).

`ml_is_attack` is always derived from `ml_label` via
`rule_label.is_attack()` — labels other than `Etc` are treated as
attacks — so no separate binary model is needed.

To train a model, see [`training/README.md`](training/README.md). The
default pipeline ships LightGBM; users who want a different algorithm
train it themselves and drop the resulting `multi_model.pkl` into
`MODEL_DIR` (the classifier hot-reloads on mtime change).

## Dashboard

`docker/tpotinit/dist/etc/objects/kibana_export_ko.ndjson` includes the
`ML Analysis - Honeypot Attack Classification` dashboard with four
panels:

- Attack Type Distribution (horizontal bar)
- Attacks by Time (stacked histogram, `ml_is_attack: true`)
- MITRE ATT&CK Score Distribution (range histogram)
- Attacks by Honeypot (horizontal bar, `ml_is_attack: true`)
- Multi-class Confidence Distribution (`ml_multi_conf`)

The dashboard is reachable from the T-Pot landing page → **ML Analyzer**.
