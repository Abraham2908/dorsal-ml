"""Fetch training telemetry from the Control Plane and convert to parquet format."""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

from dorsal_train.control_plane_client import fetch_training_windows

logger = logging.getLogger(__name__)


def fetch_and_save_telemetry(output_path: str, *, limit: int = 5000) -> Path:
    """Pull training windows from the Control Plane and save as parquet.

    Falls back to an empty DataFrame if the Control Plane returns no data,
    so the training pipeline can still run with static/lab sources only.
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    try:
        windows = fetch_training_windows(limit=limit)
    except Exception:
        logger.exception("telemetry_fetch_failed — falling back to empty dataset")
        windows = []

    if not windows:
        logger.warning("no_telemetry_windows_available — dynamic source will be empty")
        df = pd.DataFrame()
    else:
        df = pd.DataFrame(windows)
        logger.info("telemetry_fetched rows=%d", len(df))

    df.to_parquet(out, index=False)
    return out
