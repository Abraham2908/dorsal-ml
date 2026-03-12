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
) -> Path:
    del host
    del days

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
    parser.add_argument("--host", required=True, help="ClickHouse host (kept for API compatibility)")
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
    args = parser.parse_args()

    fetch_telemetry_snapshot(
        host=args.host,
        days=args.days,
        output=args.output,
        input_path=args.input,
        fallback_synthetic=not args.no_synthetic_fallback,
    )


if __name__ == "__main__":
    main()
