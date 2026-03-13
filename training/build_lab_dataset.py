"""CLI wrapper to build the lab dataset from gateway logs + agent findings."""

from __future__ import annotations

import argparse

from training.gateway_correlator import build_labeled_dataset_from_lab


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Build labeled lab dataset from gateway + agent runs")
    parser.add_argument("--gateway-log", required=True, help="Path to gateway JSONL")
    parser.add_argument("--campaign-id", default="campaign_lab_default", help="Campaign identifier")
    parser.add_argument("--target-app", default="unknown", help="Target app name")
    parser.add_argument("--lab-run-id", help="Optional lab run identifier (defaults to campaign id)")
    parser.add_argument("--is-replay", action="store_true", help="Mark traffic as replay")
    parser.add_argument(
        "--shannon-dirs",
        help="Comma-separated Shannon session dirs",
    )
    parser.add_argument(
        "--strix-dirs",
        help="Comma-separated Strix run dirs",
    )
    parser.add_argument(
        "--time-window-seconds",
        type=float,
        default=5.0,
        help="Temporal window used by confirmed_time_window tier",
    )
    parser.add_argument(
        "--output",
        default="./data/intermediate/dataset_lab.parquet",
        help="Output parquet path",
    )
    parser.add_argument("--manifest-path", help="Optional output path for JSON lab manifest")

    args = parser.parse_args()
    build_labeled_dataset_from_lab(
        gateway_log_path=args.gateway_log,
        shannon_session_dirs=_split_csv(args.shannon_dirs),
        strix_run_dirs=_split_csv(args.strix_dirs),
        output_path=args.output,
        time_window_seconds=args.time_window_seconds,
        campaign_id=args.campaign_id,
        target_app=args.target_app,
        lab_run_id=args.lab_run_id,
        is_replay=args.is_replay,
        manifest_path=args.manifest_path,
    )


if __name__ == "__main__":
    main()
