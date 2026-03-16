"""Parser for CIC-IDS 2017/2018 CSV snapshots."""

from __future__ import annotations

import csv
from pathlib import Path

from loguru import logger


def _normalize_category(value: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        return "network_attack"
    return text.replace(" ", "_").replace("-", "_").replace("/", "_")


def _is_attack(label_value: str) -> bool:
    label = (label_value or "").strip().lower()
    return label not in {"", "benign", "normal"}


def _payload_from_row(row: dict[str, str]) -> str:
    cols = [
        "flow duration",
        "total fwd packets",
        "total backward packets",
        "flow bytes/s",
        "flow packets/s",
        "fwd packet length max",
        "bwd packet length max",
        "syn flag count",
        "rst flag count",
        "psh flag count",
        "ack flag count",
        "average packet size",
    ]
    payload_parts: list[str] = []
    lowered = {k.lower(): v for k, v in row.items()}
    for col in cols:
        val = lowered.get(col, "")
        if str(val).strip():
            payload_parts.append(f"{col.replace(' ', '_')}={val}")
    return " ".join(payload_parts)


def parse_cic_ids(dataset_dir: str | Path, max_rows: int = 300_000) -> list[dict]:
    """Parse CIC-IDS local CSV files into attack/benign records."""
    root = Path(dataset_dir)
    if not root.exists():
        raise FileNotFoundError(f"CIC-IDS path not found: {root}")

    csv_files = sorted(root.rglob("*.csv"))
    records: list[dict] = []
    if not csv_files:
        logger.warning(f"CIC-IDS path has no CSV files: {root}")
        return records

    for csv_path in csv_files:
        with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as file:
            reader = csv.DictReader(file)
            for idx, row in enumerate(reader):
                if idx >= max_rows:
                    break
                lowered = {k.lower(): v for k, v in row.items()}
                label_text = lowered.get("label", "")
                is_attack = _is_attack(label_text)
                category = _normalize_category(label_text)
                records.append(
                    {
                        "payload": _payload_from_row(row),
                        "method": "GET",
                        "path": "/network/cic/flow",
                        "body": "",
                        "source": "CIC-IDS",
                        "source_file": str(csv_path.relative_to(root)),
                        "category": category if is_attack else "benign_flow",
                        "severity": "high" if is_attack else "info",
                        "evidence": "",
                        "validated": True,
                        "label": 1 if is_attack else 0,
                        "label_confidence": 0.95 if is_attack else 0.99,
                        "scenario_type": "public_flow_dataset",
                        "attack_family": category if is_attack else "benign_flow",
                        "attack_technique": category if is_attack else "benign_flow",
                        "validation_tier": "silver" if is_attack else "gold",
                        "effect_outcome": "attempt_only" if is_attack else "benign_confirmed",
                        "is_replay": False,
                    }
                )
        if len(records) >= max_rows:
            break

    logger.info(f"CIC-IDS parsed records: {len(records)}")
    return records[:max_rows]
