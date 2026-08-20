"""Configuration for the StegoSecure Flask application.

Paths are resolved so the app behaves correctly both when run normally and when
packaged with PyInstaller:

* Writable data (SQLite database, uploads, output) lives next to the running
  program (the source folder in development, or the executable's folder when
  frozen) - never inside PyInstaller's temporary ``_MEIPASS`` directory.
* Read-only bundled assets (templates, static) are resolved via
  :func:`resource_path`, which uses ``_MEIPASS`` when frozen.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Directory of this source file (used for bundled read-only assets in dev).
_SOURCE_DIR = Path(__file__).resolve().parent

# RUNTIME_DIR is the writable application root.
if getattr(sys, "frozen", False):
    # Running as a PyInstaller executable: use the executable's folder.
    RUNTIME_DIR = Path(sys.executable).resolve().parent
else:
    RUNTIME_DIR = _SOURCE_DIR

BASE_DIR = RUNTIME_DIR
UPLOAD_DIR = RUNTIME_DIR / "uploads"
OUTPUT_DIR = RUNTIME_DIR / "output"
DATABASE_PATH = RUNTIME_DIR / "data.db"

# The final stego image is always written here.
OUTPUT_IMAGE_NAME = "encrypted_image.png"

# Allowed upload extensions (validated together with real image content).
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif"}

# Maximum accepted upload size: 20 MB.
MAX_CONTENT_LENGTH = 20 * 1024 * 1024

# A demo account is seeded on startup so the app can be shown/tested
# immediately (useful for an academic viva/demo).
DEMO_FULL_NAME = "Demo User"
DEMO_USERNAME = "demo"
DEMO_EMAIL = "demo@stegosecure.local"
DEMO_PASSWORD = "demo1234"


def resource_path(relative: str) -> str:
    """Return an absolute path to a bundled read-only resource.

    Works in development and inside a PyInstaller bundle (``sys._MEIPASS``).
    """
    base = getattr(sys, "_MEIPASS", str(_SOURCE_DIR))
    return str(Path(base) / relative)


class Config:
    """Flask configuration object."""

    # Configurable secret key with a development fallback.
    SECRET_KEY = os.environ.get(
        "STEGOSECURE_SECRET_KEY", "stegosecure-dev-secret-change-me"
    )
    MAX_CONTENT_LENGTH = MAX_CONTENT_LENGTH

    # SQLAlchemy / SQLite.
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DATABASE_PATH}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Sensible session cookie hardening for a demo/production-style app.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
