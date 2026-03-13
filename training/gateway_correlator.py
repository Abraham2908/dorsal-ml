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

from training.contracts import now_iso, source_family


def _scenario_type_from_source_family(source_family_value: str) -> str:
    if source_family_value.startswith("dast_"):
        return "scanner_dast"
    if source_family_value.startswith("agent_"):
        return "agent_attack"
    if source_family_value == "payload_repo":
        return "public_payload"
    if source_family_value == "synthetic":
        return "legit_background"
    return "unknown"


def _validation_tier_from_match_tier(match_tier: str) -> str:
    if match_tier == "confirmed_exact":
        return "gold"
    if match_tier == "confirmed_time_window":
        return "silver"
    return "bronze"


def _effect_outcome_from_label(label: int) -> str:
    if label == 1:
        return "attempt_only"
    return "unknown"


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
    campaign_id: str = "campaign_lab_default",
    target_app: str = "unknown",
    lab_run_id: str | None = None,
    is_replay: bool = False,
) -> pd.DataFrame:
    resolved_lab_run_id = lab_run_id or campaign_id
    out = gateway_df.copy()
    out["label"] = 0
    out["label_confidence"] = 0.0
    out["category"] = "normal"
    out["matched_finding"] = ""
    out["match_tier"] = "unmatched"
    out["validation_tier"] = "bronze"
    out["effect_outcome"] = "unknown"
    out["scenario_type"] = "unknown"
    out["target_app"] = target_app or "unknown"
    out["attack_family"] = "unknown"
    out["attack_technique"] = "unknown"
    out["campaign_id"] = campaign_id
    out["lab_run_id"] = resolved_lab_run_id
    out["is_replay"] = bool(is_replay)
    out["observed_at"] = out["timestamp"].astype(str) if "timestamp" in out.columns else now_iso()

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
        category = str(best_finding.get("category", "unknown"))
        out.at[idx, "category"] = category
        out.at[idx, "matched_finding"] = str(
            best_finding.get("title", best_finding.get("finding_id", ""))
        )
        finding_source_family = source_family(str(best_finding.get("source", "unknown")))
        out.at[idx, "scenario_type"] = _scenario_type_from_source_family(finding_source_family)
        out.at[idx, "attack_family"] = category
        out.at[idx, "attack_technique"] = category
        out.at[idx, "validation_tier"] = _validation_tier_from_match_tier(best_tier)

        if best_tier == "confirmed_exact":
            out.at[idx, "label"] = 1
            out.at[idx, "label_confidence"] = 0.99
        elif best_tier == "confirmed_time_window":
            out.at[idx, "label"] = 1
            out.at[idx, "label_confidence"] = 0.90
        else:
            out.at[idx, "label"] = 0
            out.at[idx, "label_confidence"] = 0.40

        out.at[idx, "effect_outcome"] = _effect_outcome_from_label(int(out.at[idx, "label"]))

    logger.info("Correlation summary:")
    for tier, count in out["match_tier"].value_counts().items():
        logger.info(f"  {tier}: {count}")
    for tier, count in out["validation_tier"].value_counts().items():
        logger.info(f"  validation_tier={tier}: {count}")
    logger.info(f"  positives (label=1): {(out['label'] == 1).sum()}")
    return out


def build_labeled_dataset_from_lab(
    gateway_log_path: str | Path,
    shannon_session_dirs: list[str | Path] | None = None,
    strix_run_dirs: list[str | Path] | None = None,
    output_path: str = "./data/intermediate/dataset_lab.parquet",
    time_window_seconds: float = 5.0,
    campaign_id: str = "campaign_lab_default",
    target_app: str = "unknown",
    lab_run_id: str | None = None,
    is_replay: bool = False,
    manifest_path: str | None = None,
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
        campaign_id=campaign_id,
        target_app=target_app,
        lab_run_id=lab_run_id,
        is_replay=is_replay,
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    labeled.to_parquet(output, index=False)

    if manifest_path:
        manifest_out = Path(manifest_path)
    else:
        manifest_out = Path("reports") / f"dataset_lab_manifest_{campaign_id}.json"
    manifest_out.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": "2.0",
        "generated_at": now_iso(),
        "campaign_id": campaign_id,
        "target_app": target_app or "unknown",
        "lab_run_id": lab_run_id or campaign_id,
        "is_replay": bool(is_replay),
        "inputs": {
            "gateway_log_path": str(gateway_log_path),
            "shannon_session_dirs": [str(p) for p in (shannon_session_dirs or [])],
            "strix_run_dirs": [str(p) for p in (strix_run_dirs or [])],
            "time_window_seconds": float(time_window_seconds),
        },
        "artifacts": {
            "dataset_path": str(output),
        },
        "distributions": {
            "labels": labeled["label"].value_counts().to_dict(),
            "match_tiers": labeled["match_tier"].value_counts().to_dict(),
            "validation_tiers": labeled["validation_tier"].value_counts().to_dict(),
            "effect_outcomes": labeled["effect_outcome"].value_counts().to_dict(),
            "scenario_types": labeled["scenario_type"].value_counts().to_dict(),
        },
    }
    with open(manifest_out, "w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=2)

    logger.info(f"Labeled dataset written: {output}")
    logger.info(f"Lab manifest written: {manifest_out}")
    return labeled
