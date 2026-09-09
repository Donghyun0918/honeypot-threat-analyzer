FROM python:3.11-slim AS builder

WORKDIR /opt/llm-analyzer

COPY dist/requirements.txt .

RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/llm-analyzer

COPY --from=builder /install /usr/local

WORKDIR /opt/llm-analyzer

COPY dist/ ./

RUN groupadd -g 2000 lla \
 && useradd  -u 2000 -g 2000 -d /opt/llm-analyzer -s /sbin/nologin lla \
 && chown -R lla:lla /opt/llm-analyzer \
 && mkdir -p /data/llm-analyzer \
 && chown -R lla:lla /data

# STATE_DIR must exist in the image and be owned by the runtime user: Docker
# seeds an empty named volume from the image path *including ownership*, so
# without this the volume mounts as root:root and the non-root process cannot
# persist its cursor (it then re-bootstraps the whole window on every restart).
VOLUME /data/llm-analyzer

USER lla

ENTRYPOINT ["python", "-u", "analyze.py"]
