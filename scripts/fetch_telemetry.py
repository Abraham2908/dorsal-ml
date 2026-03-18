#!/usr/bin/env python3
"""Fetch or synthesize anonymized telemetry snapshots for Layer-3 training."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import pandas as pd
from loguru import logger

# Allow `python scripts/fetch_telemetry.py` from repo root without editable install.
if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from parsers.gateway_telemetry_parser import generate_synthetic_telemetry


def fetch_telemetry_snapshot(
    host: str,
    days: int,
    output: str,
    input_path: str | None = None,
    fallback_synthetic: bool = True,
    control_plane: bool = False,
) -> Path:
    """Fetch telemetry from a local file, the Control Plane API, or synthetic fallback.

    Args:
        host: Control Plane host URL (used when control_plane=True).
        days: Unused legacy arg retained for API compatibility.
        output: Output parquet path.
        input_path: Optional local file (parquet/csv/tsv).
        fallback_synthetic: If True, generate synthetic data when no source is available.
        control_plane: If True, fetch live telemetry windows from the Control Plane API.
    """
    del days

    if control_plane:
        try:
            from dorsal_train.control_plane_client import fetch_training_windows
            import os
            os.environ.setdefault("CONTROL_PLANE_URL", host)
            windows = fetch_training_windows(limit=10000)
            if windows:
                df = pd.DataFrame(windows)
                out = Path(output)
                out.parent.mkdir(parents=True, exist_ok=True)
                df.to_parquet(out, index=False)
                logger.info(f"Control Plane telemetry fetched: {len(df)} rows → {out}")
                return out
            logger.warning("Control Plane returned no telemetry windows; falling back.")
        except Exception as exc:
            logger.warning(f"Control Plane fetch failed: {exc}; falling back.")
        if not fallback_synthetic:
            raise RuntimeError("Control Plane telemetry unavailable and synthetic fallback disabled.")

    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)

    if input_path:
        source = Path(input_path)
        if not source.exists():
            raise FileNotFoundError(f"Input telemetry source not found: {source}")
        if source.suffix.lower() == ".parquet":
            df = pd.read_parquet(source)
        elif source.suffix.lower() in {".csv", ".tsv"}:
            sep = "\t" if source.suffix.lower() == ".tsv" else ","
            df = pd.read_csv(source, sep=sep)
        else:
            raise ValueError("Unsupported input format. Use parquet/csv/tsv.")
        df.to_parquet(out, index=False)
        logger.info(f"Telemetry snapshot copied from {source} to {out}")
        return out

    if fallback_synthetic:
        logger.warning(
            "No upstream connector configured for ClickHouse in this repository. "
            "Generating synthetic telemetry snapshot instead."
        )
        df = generate_synthetic_telemetry(
            n_tenants=30,
            n_endpoints_per_tenant=15,
            n_hours=24 * 14,
            attack_ratio=0.02,
        )
        df.to_parquet(out, index=False)
        logger.info(f"Synthetic telemetry snapshot written: {out}")
        return out

    raise RuntimeError("No telemetry source provided and synthetic fallback disabled.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch telemetry snapshot for Layer-3 training")
    parser.add_argument("--host", required=True, help="Control Plane URL or legacy ClickHouse host")
    parser.add_argument("--days", type=int, default=14)
    parser.add_argument("--output", required=True, help="Output parquet path")
    parser.add_argument(
        "--input",
        help="Optional local telemetry file (parquet/csv/tsv). If absent, synthetic snapshot is generated.",
    )
    parser.add_argument(
        "--no-synthetic-fallback",
        action="store_true",
        help="Fail instead of generating synthetic data when no input source is provided.",
    )
    parser.add_argument(
        "--control-plane",
        action="store_true",
        help="Fetch live telemetry from the Dorsal Control Plane API at --host.",
    )
    args = parser.parse_args()

    fetch_telemetry_snapshot(
        host=args.host,
        days=args.days,
        output=args.output,
        input_path=args.input,
        fallback_synthetic=not args.no_synthetic_fallback,
        control_plane=args.control_plane,
    )


if __name__ == "__main__":
    main()
