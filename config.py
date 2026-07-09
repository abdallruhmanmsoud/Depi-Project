"""
Configuration for the Forensics Dashboard.
Admin can customize settings here.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------- Upload ----------
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
MAX_CONTENT_LENGTH = 512 * 1024 * 1024  # 512 MB

# ---------- Reports ----------
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")

# ---------- Tools ----------
TOOLS_FOLDER = os.path.join(BASE_DIR, "tools")

# ---------- Flask ----------
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-me-in-production")
DEBUG = os.environ.get("FLASK_DEBUG", "1") == "1"

# ---------- Logging ----------
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
