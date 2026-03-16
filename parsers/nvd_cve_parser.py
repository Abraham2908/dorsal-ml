"""Parser for NVD CVE local snapshots."""

from __future__ import annotations

import json
from pathlib import Path

from loguru import logger


def _map_category(text: str) -> str:
    lower = text.lower()
    if "sql" in lower:
        return "sqli"
    if "cross-site scripting" in lower or " xss" in lower:
        return "xss"
    if "path traversal" in lower or "directory traversal" in lower:
        return "path_traversal"
    if "ssrf" in lower or "server-side request forgery" in lower:
        return "ssrf"
    if "command injection" in lower:
        return "command_injection"
    if "authentication" in lower or "authorization" in lower or "bypass" in lower:
        return "auth_bypass"
    return "known_vuln"


def _extract_cve_items(payload: dict) -> list[dict]:
    if isinstance(payload.get("vulnerabilities"), list):
        rows = []
        for item in payload["vulnerabilities"]:
            cve = item.get("cve")
            if isinstance(cve, dict):
                rows.append(cve)
        return rows
    if isinstance(payload.get("CVE_Items"), list):
        return [row for row in payload["CVE_Items"] if isinstance(row, dict)]
    return []


def parse_nvd_cve_snapshot(snapshot_file: str | Path, max_records: int = 80_000) -> list[dict]:
    """Parse NVD snapshot JSON into attack seed records."""
    path = Path(snapshot_file)
    if not path.exists():
        raise FileNotFoundError(f"NVD snapshot file not found: {path}")

    with open(path, "r", encoding="utf-8", errors="replace") as file:
        payload = json.load(file)
    items = _extract_cve_items(payload if isinstance(payload, dict) else {})

    records: list[dict] = []
    for item in items:
        cve_id = str(item.get("id") or item.get("CVE_data_meta", {}).get("ID") or "CVE-unknown")
        descriptions = item.get("descriptions") or []
        if isinstance(descriptions, list) and descriptions:
            text = str(descriptions[0].get("value", ""))
        else:
            description_data = item.get("description", {}).get("description_data", [])
            text = str(description_data[0].get("value", "")) if description_data else ""
        category = _map_category(text)
        severity = "high"
        metrics = item.get("metrics")
        if isinstance(metrics, dict):
            metrics_text = json.dumps(metrics).lower()
            if '"baseScore":' in metrics_text and "critical" in metrics_text:
                severity = "critical"

        short_desc = " ".join(text.split())[:400] if text else cve_id
        records.append(
            {
                "payload": f"{cve_id} {short_desc}",
                "method": "GET",
                "path": "/vuln/nvd/cve",
                "body": "",
                "source": "NVD-CVE",
                "source_file": path.name,
                "category": category,
                "severity": severity,
                "evidence": cve_id,
                "validated": True,
                "label": 1,
                "label_confidence": 0.85,
                "scenario_type": "vuln_intel_seed",
                "attack_family": category,
                "attack_technique": cve_id,
                "validation_tier": "bronze",
                "effect_outcome": "attempt_only",
                "is_replay": False,
            }
        )
        if len(records) >= max_records:
            break

    logger.info(f"NVD CVE parsed records: {len(records)}")
    return records[:max_records]
