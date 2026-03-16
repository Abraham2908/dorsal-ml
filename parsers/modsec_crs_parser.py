"""Parser for ModSecurity CRS rules snapshots."""

from __future__ import annotations

import re
from pathlib import Path

from loguru import logger


RULE_ID_RE = re.compile(r"id\s*:\s*([0-9]+)")
RULE_MSG_RE = re.compile(r"msg\s*:\s*'([^']+)'")
RULE_TAG_RE = re.compile(r"tag\s*:\s*'([^']+)'")
RULE_RX_RE = re.compile(r"@rx\s+([^\"']+)")


def _sanitize_payload(text: str) -> str:
    payload = text.strip().replace("\\", "")
    payload = re.sub(r"\s+", " ", payload)
    return payload[:300]


def parse_modsecurity_crs(crs_dir: str | Path, max_rules: int = 3_000) -> list[dict]:
    """
    Parse CRS rules and emit synthetic attack rows.

    The payload is derived from rule regex or message/tag fallback.
    """
    root = Path(crs_dir)
    if not root.exists():
        raise FileNotFoundError(f"ModSecurity CRS path not found: {root}")

    files = sorted(
        path
        for path in root.rglob("*.conf")
        if "rules" in path.parts or path.name.startswith("REQUEST-")
    )
    records: list[dict] = []
    if not files:
        logger.warning(f"ModSecurity CRS path has no .conf files: {root}")
        return records

    for file_path in files:
        rel = str(file_path.relative_to(root))
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            for line in file:
                text = line.strip()
                if not text.startswith("SecRule"):
                    continue
                rule_id_match = RULE_ID_RE.search(text)
                msg_match = RULE_MSG_RE.search(text)
                tag_match = RULE_TAG_RE.search(text)
                rx_match = RULE_RX_RE.search(text)
                if not rule_id_match:
                    continue
                rule_id = rule_id_match.group(1)
                msg = msg_match.group(1) if msg_match else "modsecurity_rule"
                tag = tag_match.group(1) if tag_match else "waf_rule"
                rx = rx_match.group(1) if rx_match else msg
                payload = _sanitize_payload(rx)
                if len(payload) < 3:
                    payload = f"rule_{rule_id}_{msg}"
                category = "waf_rule_" + tag.lower().replace(" ", "_").replace(":", "_")
                records.append(
                    {
                        "payload": payload,
                        "method": "GET",
                        "path": "/waf/modsecurity/crs",
                        "body": "",
                        "source": "ModSecurity-CRS",
                        "source_file": f"{rel}:id={rule_id}",
                        "category": category,
                        "severity": "high",
                        "evidence": msg,
                        "validated": True,
                        "label": 1,
                        "label_confidence": 0.90,
                        "scenario_type": "waf_rule_seed",
                        "attack_family": "waf_rule",
                        "attack_technique": category,
                        "validation_tier": "silver",
                        "effect_outcome": "attempt_only",
                        "is_replay": False,
                    }
                )
                if len(records) >= max_rules:
                    break
        if len(records) >= max_rules:
            break

    logger.info(f"ModSecurity CRS parsed records: {len(records)}")
    return records[:max_rules]
