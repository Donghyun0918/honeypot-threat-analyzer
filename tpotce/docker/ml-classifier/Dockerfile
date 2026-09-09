FROM python:3.11-slim AS builder

WORKDIR /opt/ml-classifier

COPY dist/requirements.txt .

RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/ml-classifier

# LightGBM's wheel uses OpenMP (libgomp) at import time
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

WORKDIR /opt/ml-classifier

COPY dist/ ./

RUN groupadd -g 2000 mlc \
 && useradd  -u 2000 -g 2000 -d /opt/ml-classifier -s /sbin/nologin mlc \
 && chown -R mlc:mlc /opt/ml-classifier

USER mlc

ENTRYPOINT ["python", "-u", "classify.py"]
