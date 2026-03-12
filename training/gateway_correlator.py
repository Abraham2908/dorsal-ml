"""
Correlate gateway traffic logs with Shannon/Strix findings.

Label policy:
- confirmed_exact / confirmed_time_window => label=1
- weak_match / unmatched => label=0

This module explicitly does NOT use `dorsal_score` to generate labels.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from loguru import logger


def load_gateway_logs(filepath: str | Path) -> pd.DataFrame:
    filepath = Path(filepath)
    if not filepath.exists():
        logger.error(f"Gateway logs not found: {filepath}")
        return pd.DataFrame()

    records = []
    with open(filepath, "r", encoding="utf-8") as file:
        for line_num, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                if line_num <= 5:
                    logger.warning(f"Invalid JSON line at {line_num}")

    df = pd.DataFrame(records)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    return df


def load_agent_findings(
    shannon_dirs: list[str | Path] | None = None,
    strix_dirs: list[str | Path] | None = None,
) -> pd.DataFrame:
    from parsers.shannon_parser import parse_shannon_session
    from parsers.strix_parser import parse_strix_run

    rows: list[dict] = []
    for directory in shannon_dirs or []:
        rows.extend(parse_shannon_session(directory))
    for directory in strix_dirs or []:
        rows.extend(parse_strix_run(directory))

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    return df


def _match_tier(
    req: pd.Series,
    finding: pd.Series,
    time_window_seconds: float,
) -> str | None:
    req_path = str(req.get("path", "/")).lower()
    req_method = str(req.get("method", "GET")).upper()
    req_body = str(req.get("body", "")).lower()
    req_query = str(req.get("query_string", "")).lower()
    req_full = f"{req_path} {req_query} {req_body}"

    finding_payload = str(finding.get("payload", "")).lower()
    finding_path = str(finding.get("path", "")).lower()
    finding_method = str(finding.get("method", "GET")).upper()

    if finding_payload and finding_path and finding_path in req_path and finding_payload in req_full:
        return "confirmed_exact"

    req_ts = req.get("timestamp")
    finding_ts = finding.get("timestamp")
    if (
        finding_path
        and finding_path in req_path
        and finding_method == req_method
        and pd.notna(req_ts)
        and pd.notna(finding_ts)
    ):
        delta = abs((req_ts - finding_ts).total_seconds())
        if delta <= time_window_seconds:
            return "confirmed_time_window"

    if finding_payload and len(finding_payload) >= 4 and finding_payload in req_full:
        return "weak_match"

    if finding_path and finding_path in req_path and finding_method == req_method:
        return "weak_match"

    return None


def correlate_logs_with_findings(
    gateway_df: pd.DataFrame,
    findings_df: pd.DataFrame,
    time_window_seconds: float = 5.0,
) -> pd.DataFrame:
    out = gateway_df.copy()
    out["label"] = 0
    out["label_confidence"] = 0.0
    out["category"] = "normal"
    out["matched_finding"] = ""
    out["match_tier"] = "unmatched"

    if findings_df.empty:
        logger.warning("No findings available, returning unmatched labels only.")
        return out

    for idx, req in out.iterrows():
        best_finding = None
        best_tier = None
        for _, finding in findings_df.iterrows():
            tier = _match_tier(req, finding, time_window_seconds)
            if tier is None:
                continue
            if tier == "confirmed_exact":
                best_finding = finding
                best_tier = tier
                break
            if tier == "confirmed_time_window" and best_tier != "confirmed_time_window":
                best_finding = finding
                best_tier = tier
            elif tier == "weak_match" and best_tier is None:
                best_finding = finding
                best_tier = tier

        if best_tier is None:
            continue

        out.at[idx, "match_tier"] = best_tier
        out.at[idx, "category"] = str(best_finding.get("category", "unknown"))
        out.at[idx, "matched_finding"] = str(
            best_finding.get("title", best_finding.get("finding_id", ""))
        )

        if best_tier == "confirmed_exact":
            out.at[idx, "label"] = 1
            out.at[idx, "label_confidence"] = 0.99
        elif best_tier == "confirmed_time_window":
            out.at[idx, "label"] = 1
            out.at[idx, "label_confidence"] = 0.90
        else:
            out.at[idx, "label"] = 0
            out.at[idx, "label_confidence"] = 0.40

    logger.info("Correlation summary:")
    for tier, count in out["match_tier"].value_counts().items():
        logger.info(f"  {tier}: {count}")
    logger.info(f"  positives (label=1): {(out['label'] == 1).sum()}")
    return out


def build_labeled_dataset_from_lab(
    gateway_log_path: str | Path,
    shannon_session_dirs: list[str | Path] | None = None,
    strix_run_dirs: list[str | Path] | None = None,
    output_path: str = "./data/intermediate/dataset_lab.parquet",
    time_window_seconds: float = 5.0,
) -> pd.DataFrame:
    gateway_df = load_gateway_logs(gateway_log_path)
    if gateway_df.empty:
        logger.error("No gateway logs loaded.")
        return pd.DataFrame()

    findings_df = load_agent_findings(shannon_dirs=shannon_session_dirs, strix_dirs=strix_run_dirs)
    labeled = correlate_logs_with_findings(
        gateway_df=gateway_df,
        findings_df=findings_df,
        time_window_seconds=time_window_seconds,
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    labeled.to_parquet(output, index=False)
    logger.info(f"Labeled dataset written: {output}")
    return labeled
