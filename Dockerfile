FROM python:3.11-slim

# Environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# System dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy dependency files first (cache optimization)
COPY requirements.txt dev-requirements.txt pyproject.toml setup.cfg ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy full project
COPY . .

# Install project as package
RUN pip install --no-cache-dir .

# Default command (runs CLI)
CMD ["python", "-m", "security_playbooks.cli.main"]
