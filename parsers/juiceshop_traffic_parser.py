"""Parser for OWASP Juice Shop traffic snapshots."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from loguru import logger


def _safe_label(record: dict[str, Any]) -> int:
    if "label" in record:
        try:
            return int(record["label"])
        except (TypeError, ValueError):
            return 0
    scenario = str(record.get("scenario_type", "")).lower()
    category = str(record.get("category", "")).lower()
    if "attack" in scenario or category not in {"", "normal", "benign"}:
        return 1
    return 0


def _normalize(record: dict[str, Any], source_file: str) -> dict:
    label = _safe_label(record)
    category = str(record.get("category") or ("web_attack" if label == 1 else "benign_flow"))
    method = str(record.get("method") or "GET").upper()
    path = str(record.get("path") or "/")
    query = str(record.get("query_string") or "")
    body = str(record.get("body") or "")
    payload = " ".join(part for part in [query, body] if part).strip() or f"{method} {path}"
    return {
        "payload": payload[:1000],
        "method": method,
        "path": path,
        "body": body[:1000],
        "source": "OWASP Juice Shop",
        "source_file": source_file,
        "category": category,
        "severity": "high" if label == 1 else "info",
        "evidence": "",
        "validated": True,
        "label": label,
        "label_confidence": 0.95 if label == 1 else 0.99,
        "scenario_type": str(record.get("scenario_type") or ("agent_attack" if label == 1 else "legit_background")),
        "attack_family": str(record.get("attack_family") or category),
        "attack_technique": str(record.get("attack_technique") or category),
        "validation_tier": "silver" if label == 1 else "gold",
        "effect_outcome": "attempt_only" if label == 1 else "benign_confirmed",
        "is_replay": bool(record.get("is_replay", False)),
    }


def parse_juiceshop_traffic(dataset_dir: str | Path, max_rows: int = 250_000) -> list[dict]:
    """Parse JSONL traffic snapshots generated from Juice Shop campaigns."""
    root = Path(dataset_dir)
    if not root.exists():
        raise FileNotFoundError(f"Juice Shop traffic path not found: {root}")

    files = sorted(path for path in root.rglob("*.jsonl"))
    records: list[dict] = []
    if not files:
        logger.warning(f"Juice Shop traffic path has no JSONL files: {root}")
        return records

    for path in files:
        rel = str(path.relative_to(root))
        with open(path, "r", encoding="utf-8", errors="replace") as file:
            for line in file:
                text = line.strip()
                if not text:
                    continue
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    records.append(_normalize(payload, rel))
                if len(records) >= max_rows:
                    break
        if len(records) >= max_rows:
            break

    logger.info(f"Juice Shop traffic parsed records: {len(records)}")
    return records[:max_rows]
