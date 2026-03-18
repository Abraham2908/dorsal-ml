"""Authenticated HTTP client for communicating with the Dorsal Control Plane."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import httpx

from dorsal_train.config import (
    CONTROL_PLANE_ADMIN_EMAIL,
    CONTROL_PLANE_ADMIN_PASSWORD,
    CONTROL_PLANE_URL,
)

logger = logging.getLogger(__name__)

_TOKEN_CACHE: dict[str, str] = {}


def _login() -> str:
    """Obtain a fresh access token from the control plane."""
    resp = httpx.post(
        f"{CONTROL_PLANE_URL}/api/v1/auth/login",
        json={"email": CONTROL_PLANE_ADMIN_EMAIL, "password": CONTROL_PLANE_ADMIN_PASSWORD},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    token: str = data["access_token"]
    return token


def _get_token() -> str:
    if "access" not in _TOKEN_CACHE:
        _TOKEN_CACHE["access"] = _login()
    return _TOKEN_CACHE["access"]


def _authed_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_get_token()}"}


def _refresh_and_retry(method: str, url: str, **kwargs: Any) -> httpx.Response:
    """Call an endpoint; if 401, refresh token and retry once."""
    headers = _authed_headers()
    resp = httpx.request(method, url, headers=headers, timeout=60, **kwargs)
    if resp.status_code == 401:
        _TOKEN_CACHE.clear()
        headers = _authed_headers()
        resp = httpx.request(method, url, headers=headers, timeout=60, **kwargs)
    resp.raise_for_status()
    return resp


# ---------------------------------------------------------------------------
# Training runs
# ---------------------------------------------------------------------------


def update_training_run(run_id: int, *, status: str, **extra: Any) -> None:
    """PATCH /api/v1/admin/training/runs/{id} with status and optional fields."""
    payload: dict[str, Any] = {"status": status, **extra}
    _refresh_and_retry("PATCH", f"{CONTROL_PLANE_URL}/api/v1/admin/training/runs/{run_id}", json=payload)
    logger.info("training_run_updated run_id=%s status=%s", run_id, status)


# ---------------------------------------------------------------------------
# ML model upload
# ---------------------------------------------------------------------------


def upload_model_bundle(
    *,
    name: str,
    version: str,
    model_type: str,
    description: str,
    bundle_path: Path,
) -> dict[str, Any]:
    """POST /api/v1/admin/ml-models — multipart upload of a model bundle."""
    with bundle_path.open("rb") as fh:
        resp = _refresh_and_retry(
            "POST",
            f"{CONTROL_PLANE_URL}/api/v1/admin/ml-models",
            data={
                "name": name,
                "version": version,
                "model_type": model_type,
                "description": description,
            },
            files={"file": (bundle_path.name, fh, "application/octet-stream")},
        )
    data: dict[str, Any] = resp.json()
    logger.info("model_uploaded name=%s version=%s id=%s", name, version, data.get("id"))
    return data


# ---------------------------------------------------------------------------
# Telemetry export
# ---------------------------------------------------------------------------


def fetch_training_windows(*, limit: int = 5000) -> list[dict[str, Any]]:
    """GET /api/v1/telemetry/training/export — returns training telemetry windows."""
    resp = _refresh_and_retry(
        "GET",
        f"{CONTROL_PLANE_URL}/api/v1/telemetry/training/export",
        params={"limit": limit},
    )
    data = resp.json()
    windows: list[dict[str, Any]] = data.get("windows", [])
    logger.info("telemetry_export_fetched count=%d", len(windows))
    return windows
