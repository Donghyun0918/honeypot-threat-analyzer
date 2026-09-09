# ml-classifier · training pipeline

Offline scripts that convert T-Pot honeypot logs into a labeled dataset
and train the LightGBM multi-class model that `ml-classifier` (the
runtime sidecar) consumes.

> **Not part of the runtime image.** This directory is a developer tool
> — it's run by hand (or via the threat-console UI) when you want to
> train a new model on fresh data. The runtime container only needs the
> resulting `multi_model.pkl` + `encoders.json`.

## Quickstart

```bash
# 1) install training deps in a venv (host machine, not the container)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2) build a dataset from the ES side (auto mode)
python build_dataset.py --es http://127.0.0.1:64298 \
                       --since now-7d --max 50000 \
                       --out dataset.csv \
                       --encoders-out encoders.json

# 3) train + evaluate (80/20 auto-split)
python train.py --csv dataset.csv --encoders encoders.json --out-dir models/

# 4) drop the artefacts into the runtime container
docker cp models/multi_model.pkl   ml-classifier:/opt/ml-classifier/models/
docker cp models/encoders.json     ml-classifier:/opt/ml-classifier/models/
docker restart ml-classifier
# logs should now print "multi model loaded"
```

The runtime classifier loads `multi_model.pkl` from `MODEL_DIR` (default
`/opt/ml-classifier/models`) and stamps each ES document with
`model_used: "ml"`. If the file is absent, it falls back to deterministic
rules (`model_used: "rule"`).

`ml_is_attack` is derived from the predicted label via
`rule_label.is_attack()` — labels other than `Etc` are treated as
attacks — so this pipeline only trains the multi-class model.

## Two ways to provide labelled data

### Auto mode — pull from ES, label by rules (weak supervision)

`build_dataset.py` queries `logstash-*`, runs every document through
`feature_extract.py` (16 features) and `rule_label.py` (initial
weak label), and writes one CSV. Then `train.py --csv` does an 80/20
stratified split.

This is the path that makes sense in production: rules cover the easy
cases, the model learns to generalize the feature patterns, and
hold-out evaluation tells you how well it's doing.

### Manual mode — bring your own train/test files

If you've hand-curated a dataset (or split via `make_split.py`,
or want reproducible benchmarking), pass two files:

```bash
python train.py \
    --train-csv my_train.csv \
    --test-csv  my_test.csv \
    --encoders  encoders.json \
    --out-dir   models/
```

CSV schema (header row required, comma-separated):

```
hour,is_night,day_of_week,dst_port,protocol,source_honeypot,event_type,
login_success,duration,login_attempts,cmd_length,special_char_cnt,
pipe_count,has_wget,has_curl,has_reverse_shell,label
```

`label` ∈ `{Recon, Brute Force, Malware, Intrusion, Etc}`. Categorical
columns (`protocol`, `source_honeypot`, `event_type`) are integer-coded;
use the same `encoders.json` you built when extracting features so the
codes line up at inference time.

## Output artefacts (`models/`)

| File                  | Purpose                                              |
|-----------------------|------------------------------------------------------|
| `multi_model.pkl`     | LightGBM 5-class classifier                          |
| `encoders.json`       | Stable category-to-int mapping for inference         |
| `metrics.json`        | Accuracy, macro-F1, per-class precision/recall/F1    |
| `confusion_multi.txt` | ASCII confusion matrix                               |

## Tuning

`train.py` flags worth knowing:

| Flag                | Default | Notes                                          |
|---------------------|---------|------------------------------------------------|
| `--n-estimators`    | 200     | LightGBM boosting rounds                       |
| `--max-depth`       | None    | -1 (unlimited) when None — lower if overfitting |
| `--test-size`       | 0.2     | Auto-split ratio                               |
| `--seed`            | 42      | Reproducibility                                |

`class_weight="balanced"` is set by default — necessary because real
T-Pot traffic is heavily skewed toward `Recon`.

## Bring your own algorithm

The pipeline ships LightGBM only. If you prefer scikit-learn's
RandomForest, XGBoost, a neural net, or anything else:

1. Train it on the same 16 feature columns + label schema above.
2. Pickle the fitted estimator as `multi_model.pkl` (must implement
   `predict()` and `predict_proba()` returning class strings matching
   `{Recon, Brute Force, Malware, Intrusion, Etc}`).
3. Drop it into `MODEL_DIR` (or upload through the threat-console UI).
   The classifier hot-reloads on mtime change — no restart needed.

The runtime makes no assumptions about which library produced the
model; only the sklearn-compatible `predict` interface is required.
