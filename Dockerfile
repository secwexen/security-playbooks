FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/opt/playbooks" \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/playbooks

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    build-essential \
    make \
    yara \
    suricata \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -r socadmin

COPY --chown=socadmin:socadmin requirements.txt requirements-dev.txt ./

RUN python -m pip install --no-cache-dir \
    -r requirements.txt && \
    python -m pip install --no-cache-dir \
    -r requirements-dev.txt

COPY --chown=socadmin:socadmin . .

USER socadmin

CMD ["tail", "-f", "/dev/null"]
