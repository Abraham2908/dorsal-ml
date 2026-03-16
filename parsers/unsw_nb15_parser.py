"""Parser for UNSW-NB15 CSV snapshots."""

from __future__ import annotations

import csv
from pathlib import Path

from loguru import logger


def _safe_int(value: str | None, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _is_attack(row: dict[str, str]) -> bool:
    label = row.get("label")
    attack_cat = (row.get("attack_cat") or row.get("attack category") or "").strip().lower()
    if label is not None:
        return _safe_int(label, 0) == 1
    if attack_cat:
        return attack_cat not in {"normal", "benign"}
    return False


def _category(row: dict[str, str]) -> str:
    attack_cat = (row.get("attack_cat") or row.get("attack category") or "").strip().lower()
    if not attack_cat:
        return "network_attack" if _is_attack(row) else "benign_flow"
    return attack_cat.replace(" ", "_").replace("-", "_")


def _payload_from_row(row: dict[str, str]) -> str:
    fields = [
        ("proto", row.get("proto", "")),
        ("service", row.get("service", "")),
        ("state", row.get("state", "")),
        ("spkts", row.get("spkts", "")),
        ("dpkts", row.get("dpkts", "")),
        ("sbytes", row.get("sbytes", "")),
        ("dbytes", row.get("dbytes", "")),
        ("sload", row.get("sload", "")),
        ("dload", row.get("dload", "")),
        ("sttl", row.get("sttl", "")),
        ("dttl", row.get("dttl", "")),
    ]
    return " ".join(f"{key}={value}" for key, value in fields if str(value).strip())


def parse_unsw_nb15(dataset_dir: str | Path, max_rows: int = 300_000) -> list[dict]:
    """Parse UNSW-NB15 local CSV files into attack/benign records."""
    root = Path(dataset_dir)
    if not root.exists():
        raise FileNotFoundError(f"UNSW-NB15 path not found: {root}")

    csv_files = sorted(root.rglob("*.csv"))
    records: list[dict] = []
    if not csv_files:
        logger.warning(f"UNSW-NB15 path has no CSV files: {root}")
        return records

    for csv_path in csv_files:
        with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as file:
            reader = csv.DictReader(file)
            for idx, row in enumerate(reader):
                if idx >= max_rows:
                    break
                is_attack = _is_attack(row)
                service = (row.get("service") or row.get("proto") or "network").strip().lower() or "network"
                path = f"/network/unsw/{service}"
                records.append(
                    {
                        "payload": _payload_from_row(row),
                        "method": "GET",
                        "path": path,
                        "body": "",
                        "source": "UNSW-NB15",
                        "source_file": str(csv_path.relative_to(root)),
                        "category": _category(row),
                        "severity": "medium" if is_attack else "info",
                        "evidence": "",
                        "validated": True,
                        "label": 1 if is_attack else 0,
                        "label_confidence": 0.95 if is_attack else 0.99,
                        "scenario_type": "public_flow_dataset",
                        "attack_family": _category(row),
                        "attack_technique": _category(row),
                        "validation_tier": "silver" if is_attack else "gold",
                        "effect_outcome": "attempt_only" if is_attack else "benign_confirmed",
                        "is_replay": False,
                    }
                )
        if len(records) >= max_rows:
            break

    logger.info(f"UNSW-NB15 parsed records: {len(records)}")
    return records[:max_rows]
