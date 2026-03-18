"""Environment-based configuration for the dorsal-train service."""

from __future__ import annotations

import os


def _get(key: str, default: str = "") -> str:
    return os.getenv(key, default).strip()


def _get_required(key: str) -> str:
    val = os.getenv(key, "").strip()
    if not val:
        raise RuntimeError(f"Required environment variable {key!r} is not set")
    return val


# Control Plane connectivity
CONTROL_PLANE_URL: str = _get("CONTROL_PLANE_URL", "http://localhost:8000")
CONTROL_PLANE_ADMIN_EMAIL: str = _get("CONTROL_PLANE_ADMIN_EMAIL", "root@dorsal.local")
CONTROL_PLANE_ADMIN_PASSWORD: str = _get("CONTROL_PLANE_ADMIN_PASSWORD", "Secret123")

# Training mode: "static" | "dynamic" | "all"
TRAIN_MODE: str = _get("TRAIN_MODE", "all")

# File system paths
DATA_DIR: str = _get("DATA_DIR", "/data")
MODELS_DIR: str = _get("MODELS_DIR", "/models")
LOG_DIR: str = _get("LOG_DIR", "/logs")

# Service bind
SERVICE_HOST: str = _get("SERVICE_HOST", "0.0.0.0")
SERVICE_PORT: int = int(_get("SERVICE_PORT", "8090"))

# Internal API key shared with control plane (optional; used to authenticate callbacks)
DORSAL_ML_API_KEY: str = _get("DORSAL_ML_API_KEY", "")
