"""Parser for Common Crawl sampled HTTP request snapshots."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pandas as pd
from loguru import logger


def _from_record(record: dict[str, Any], source_file: str) -> dict:
    method = str(record.get("method") or "GET").upper()
    url = str(record.get("url") or "")
    parsed = urlparse(url) if url else None
    path = parsed.path if parsed and parsed.path else str(record.get("path") or "/")
    query = parsed.query if parsed and parsed.query else str(record.get("query") or "")
    body = str(record.get("body") or "")
    payload = " ".join(part for part in [query, body, str(record.get("user_agent") or "")] if part).strip()
    if not payload:
        payload = f"{method} {path}"
    return {
        "payload": payload[:800],
        "method": method,
        "path": path or "/",
        "body": body[:800],
        "source": "CommonCrawl",
        "source_file": source_file,
        "category": "benign_web",
        "severity": "info",
        "evidence": "",
        "validated": True,
        "label": 0,
        "label_confidence": 0.99,
        "scenario_type": "public_benign_dataset",
        "attack_family": "benign_web",
        "attack_technique": "benign_web",
        "validation_tier": "gold",
        "effect_outcome": "benign_confirmed",
        "is_replay": False,
    }


def _read_json_records(path: Path) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="replace") as file:
        payload = json.load(file)
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        if isinstance(payload.get("records"), list):
            return [row for row in payload["records"] if isinstance(row, dict)]
        return [payload]
    return []


def parse_common_crawl(dataset_dir: str | Path, max_rows: int = 500_000) -> list[dict]:
    """
    Parse local Common Crawl samples.

    Supported files: .jsonl, .json, .parquet
    """
    root = Path(dataset_dir)
    if not root.exists():
        raise FileNotFoundError(f"Common Crawl path not found: {root}")

    files = sorted(
        path
        for path in root.rglob("*")
        if path.suffix.lower() in {".jsonl", ".json", ".parquet"}
    )
    records: list[dict] = []
    if not files:
        logger.warning(f"Common Crawl path has no supported files: {root}")
        return records

    for path in files:
        rel = str(path.relative_to(root))
        if path.suffix.lower() == ".jsonl":
            with open(path, "r", encoding="utf-8", errors="replace") as file:
                for line in file:
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        row = json.loads(text)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(row, dict):
                        records.append(_from_record(row, rel))
                    if len(records) >= max_rows:
                        break
        elif path.suffix.lower() == ".json":
            for row in _read_json_records(path):
                records.append(_from_record(row, rel))
                if len(records) >= max_rows:
                    break
        else:
            frame = pd.read_parquet(path)
            for row in frame.to_dict(orient="records"):
                records.append(_from_record(row, rel))
                if len(records) >= max_rows:
                    break
        if len(records) >= max_rows:
            break

    logger.info(f"Common Crawl parsed records: {len(records)}")
    return records[:max_rows]
