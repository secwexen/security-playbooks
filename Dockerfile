FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/opt/playbooks"

WORKDIR /opt/playbooks

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    make \
    yara \
    suricata \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -r socadmin

COPY --chown=socadmin:socadmin requirements.txt requirements-dev.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r requirements-dev.txt

COPY --chown=socadmin:socadmin . .

USER socadmin

CMD ["tail", "-f", "/dev/null"]
