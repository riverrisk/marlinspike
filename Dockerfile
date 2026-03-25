# ── Runtime ───────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# System deps: tshark for local live capture, libpq for psycopg2
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    tshark \
    iproute2 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application source
COPY _ms_engine.py _auth.py _models.py _config.py ./
COPY auth.py config.py models.py app.py marlinspike.py ./

COPY templates/ ./templates/
COPY static/ ./static/
COPY presets/ ./presets/

# OUI database (outside volume mount so it persists in image)
COPY data/oui.json ./oui.json

# Data dirs (will be overridden by volume mount)
RUN mkdir -p data/reports data/uploads data/submissions

# Create non-root user (needs NET_RAW for tshark)
RUN useradd -m -u 1000 marlinspike && \
    chown -R marlinspike:marlinspike /app

USER marlinspike

EXPOSE 5001/tcp

CMD ["python3", "app.py"]
