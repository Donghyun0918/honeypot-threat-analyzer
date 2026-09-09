FROM python:3.11-slim AS builder

WORKDIR /opt/threat-console

# WeasyPrint runtime deps + Korean fonts (Noto CJK)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
        libgdk-pixbuf-2.0-0 shared-mime-info \
        fonts-noto-cjk fonts-nanum \
        libgomp1 \
        curl && \
    rm -rf /var/lib/apt/lists/*

COPY threat-console/dist/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Final image ───────────────────────────────────────────────────────────
FROM python:3.11-slim

# Re-install runtime libs + fonts in final image
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
        libgdk-pixbuf-2.0-0 shared-mime-info \
        fonts-noto-cjk fonts-nanum \
        libgomp1 \
        curl && \
    rm -rf /var/lib/apt/lists/* && \
    addgroup --system --gid 2000 tpot && \
    adduser  --system --uid 2000 --gid 2000 --no-create-home tpot

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

WORKDIR /opt/threat-console
COPY threat-console/dist/ /opt/threat-console/

# Bundle the ml-classifier training scripts so threat-console can run them
# as subprocesses for the in-UI training pipeline. Also include the dist/
# helpers (feature_extract.py, rule_label.py) that the training scripts import.
COPY ml-classifier/training/                  /opt/ml-classifier-training/
COPY ml-classifier/dist/feature_extract.py    /opt/ml-classifier/dist/feature_extract.py
COPY ml-classifier/dist/rule_label.py         /opt/ml-classifier/dist/rule_label.py

USER tpot

ENV LISTEN_PORT=8080 \
    ES_HOST=http://elasticsearch:9200 \
    REPORT_DIR=/data/threat-console/reports \
    TRAIN_DIR=/data/threat-console/training \
    TRAINING_SRC=/opt/ml-classifier-training \
    MODEL_ACTIVE_DIR=/data/ml-classifier/models

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/api/health || exit 1

CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "1", "--threads", "4", "--timeout", "300", "app:app"]
