"""MarlinSpike standalone — configuration constants."""

import os

# Database
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://marlinspike:marlinspike@localhost:5432/marlinspike",
)

# Secret key for Flask sessions
SECRET_KEY = os.environ.get("SECRET_KEY", "")

# Admin bootstrap password (if empty, one is generated on first run)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")
UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
SUBMISSIONS_DIR = os.path.join(DATA_DIR, "submissions")

# MarlinSpike module path
MARLINSPIKE_PY = os.path.join(BASE_DIR, "marlinspike.py")

# Preset PCAPs (volume-backed, admin-editable at runtime)
PRESETS_DIR = os.path.join(DATA_DIR, "presets")

# Baked-in presets (copied to DATA_DIR on first boot)
PRESETS_BAKED_DIR = os.path.join(BASE_DIR, "presets")

# Upload limits
PCAP_MAX_SIZE = int(os.environ.get("PCAP_MAX_SIZE", 200 * 1024 * 1024))  # 200 MB
PCAP_PROCESS_SIZE = int(os.environ.get("PCAP_PROCESS_SIZE", 100 * 1024 * 1024))  # 100 MB

# Server
PORT = int(os.environ.get("PORT", 5001))
HOST = os.environ.get("HOST", "0.0.0.0")

# Run cleanup
RUN_CLEANUP_SECONDS = 3600

# Feature flags
ENABLE_LIVE_CAPTURE = os.environ.get("ENABLE_LIVE_CAPTURE", "false").lower() in ("true", "1", "yes")
