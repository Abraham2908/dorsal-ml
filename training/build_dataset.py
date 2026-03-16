"""
Build Layer-1 supervised dataset from local snapshots only.

This module intentionally avoids implicit network calls. All sources must be
available as local files/directories.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from loguru import logger

from parsers.acunetix_parser import parse_acunetix_json
from parsers.burp_parser import parse_burp_json, parse_burp_xml
from parsers.cic_ids_parser import parse_cic_ids
from parsers.common_crawl_parser import parse_common_crawl
from parsers.dvwa_traffic_parser import parse_dvwa_traffic
from parsers.juiceshop_traffic_parser import parse_juiceshop_traffic
from parsers.modsec_crs_parser import parse_modsecurity_crs
from parsers.nvd_cve_parser import parse_nvd_cve_snapshot
from parsers.normal_traffic_generator import generate_normal_requests
from parsers.payload_repos_parser import parse_payload_all_the_things, parse_seclists
from parsers.shannon_parser import parse_shannon_all_sessions, parse_shannon_session
from parsers.strix_parser import parse_strix_all_runs, parse_strix_run
from parsers.unsw_nb15_parser import parse_unsw_nb15
from parsers.zap_parser import parse_zap_json
from training.contracts import (
    canonical_payload_hash,
    is_synthetic_source,
    make_event_id,
    make_split_key,
    now_iso,
    source_family,
)
from utils.feature_extraction import RequestFeatures, extract_features_from_payload, shannon_entropy


_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def _safe_str(value: object, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _entropy_ngrams(text: str, n: int) -> float:
    text = text or ""
    if len(text) < n or n <= 0:
        return 0.0
    grams = [text[i : i + n] for i in range(len(text) - n + 1)]
    freq: dict[str, int] = {}
    for gram in grams:
        freq[gram] = freq.get(gram, 0) + 1
    total = len(grams)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def _shannon_enrichment(payload: str) -> dict[str, float]:
    payload = payload or ""
    length = max(len(payload), 1)
    alpha = sum(1 for c in payload if c.isalpha())
    digits = sum(1 for c in payload if c.isdigit())
    upper = sum(1 for c in payload if c.isupper())
    special = sum(1 for c in payload if not c.isalnum() and not c.isspace())
    repetition = 1.0 - (len(set(payload)) / length)
    url_encoded = 1.0 if "%" in payload and re.search(r"%[0-9a-fA-F]{2}", payload) else 0.0
    base64_like = 0.0
    if len(payload) >= 16 and len(payload) % 4 == 0 and _BASE64_RE.match(payload):
        base64_like = 1.0

    return {
        "shannon_char_entropy": shannon_entropy(payload),
        "shannon_bigram_entropy": _entropy_ngrams(payload, 2),
        "shannon_trigram_entropy": _entropy_ngrams(payload, 3),
        "shannon_repetition": max(0.0, repetition),
        "shannon_alpha_ratio": alpha / length,
        "shannon_digit_ratio": digits / length,
        "shannon_special_ratio": special / length,
        "shannon_upper_ratio": upper / length,
        "shannon_url_encoded": url_encoded,
        "shannon_base64_likely": base64_like,
    }


def _parse_csv_dirs(csv_value: str | None) -> list[str]:
    if not csv_value:
        return []
    return [part.strip() for part in csv_value.split(",") if part.strip()]


def _normal_api_types_for_profile(profile: str) -> list[str] | None:
    normalized = (profile or "default").strip().lower()
    if normalized in {"default", "all"}:
        return None
    if normalized == "b2b":
        return ["saas_b2b", "fintech"]
    if normalized == "consumer":
        return ["ecommerce", "healthtech"]
    if normalized == "fintech":
        return ["fintech"]
    if normalized == "saas":
        return ["saas_b2b"]
    return None


def _read_json_records(path: Path) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as file:
        payload = json.load(file)
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        records = payload.get("records")
        if isinstance(records, list):
            return [item for item in records if isinstance(item, dict)]
        return [payload]
    return []


def _normalize_hard_negative_record(record: dict[str, Any], source_hint: str) -> dict[str, Any]:
    payload = _safe_str(record.get("payload"))
    method = _safe_str(record.get("method"), "GET").upper()
    path = _safe_str(record.get("path"), "/")
    body = _safe_str(record.get("body"))
    return {
        "payload": payload or body or path,
        "method": method,
        "path": path,
        "body": body,
        "source": _safe_str(record.get("source"), source_hint),
        "source_file": _safe_str(record.get("source_file"), source_hint),
        "category": _safe_str(record.get("category"), "hard_negative"),
        "severity": _safe_str(record.get("severity"), "info"),
        "evidence": _safe_str(record.get("evidence"), ""),
        "validated": bool(record.get("validated", True)),
        "label": 0,
        "label_confidence": float(record.get("label_confidence", 0.99)),
        "scenario_type": _safe_str(record.get("scenario_type"), "hard_negative"),
        "attack_family": _safe_str(record.get("attack_family"), "benign_hard_negative"),
        "attack_technique": _safe_str(record.get("attack_technique"), "benign_hard_negative"),
        "validation_tier": _safe_str(record.get("validation_tier"), "gold"),
        "effect_outcome": _safe_str(record.get("effect_outcome"), "benign_confirmed"),
        "is_replay": bool(record.get("is_replay", False)),
    }


def _load_hard_negative_records(hard_negatives_path: str | None) -> list[dict[str, Any]]:
    if not hard_negatives_path:
        return []
    root = Path(hard_negatives_path)
    if not root.exists():
        raise FileNotFoundError(f"Hard negatives path not found: {root}")

    files: list[Path]
    if root.is_dir():
        files = sorted(
            p
            for p in root.rglob("*")
            if p.suffix.lower() in {".json", ".jsonl", ".parquet"}
        )
    else:
        files = [root]

    records: list[dict[str, Any]] = []
    for file_path in files:
        source_hint = f"synthetic_hard_negative:{file_path.name}"
        if file_path.suffix.lower() == ".parquet":
            df = pd.read_parquet(file_path)
            for raw in df.to_dict(orient="records"):
                records.append(_normalize_hard_negative_record(raw, source_hint=source_hint))
            continue

        if file_path.suffix.lower() == ".jsonl":
            with open(file_path, "r", encoding="utf-8") as file:
                for line in file:
                    text = line.strip()
                    if not text:
                        continue
                    raw = json.loads(text)
                    if isinstance(raw, dict):
                        records.append(_normalize_hard_negative_record(raw, source_hint=source_hint))
            continue

        for raw in _read_json_records(file_path):
            records.append(_normalize_hard_negative_record(raw, source_hint=source_hint))

    logger.info(f"   Hard negatives: +{len(records)} from {root}")
    return records


def _scenario_type_from_source_family(source_family_value: str) -> str:
    if source_family_value == "payload_repo":
        return "public_payload"
    if source_family_value.startswith("dast_"):
        return "scanner_dast"
    if source_family_value.startswith("agent_"):
        return "agent_attack"
    if source_family_value == "synthetic":
        return "legit_background"
    if source_family_value == "public_flow":
        return "public_flow_dataset"
    if source_family_value == "public_benign":
        return "public_benign_dataset"
    if source_family_value == "waf_rules":
        return "waf_rule_seed"
    if source_family_value == "vuln_feed":
        return "vuln_intel_seed"
    if source_family_value == "lab_app":
        return "app_attack_dataset"
    return "unknown"


def _validation_tier_from_confidence(label_confidence: float) -> str:
    if label_confidence >= 0.95:
        return "gold"
    if label_confidence >= 0.80:
        return "silver"
    return "bronze"


def _effect_outcome_from_label(label: int) -> str:
    if label == 1:
        return "attempt_only"
    return "unknown"


def _validate_required_static_sources(
    *,
    require_static_full: bool,
    source_paths: dict[str, str | None],
) -> None:
    if not require_static_full:
        return
    missing = [name for name, path in source_paths.items() if not path or not Path(path).exists()]
    if missing:
        raise ValueError(
            "Full static profile requested but required sources are missing: "
            + ", ".join(sorted(missing))
        )


def _collect_local_attack_records(
    payloads_dir: str | None,
    seclists_dir: str | None,
    burp_file: str | None,
    zap_file: str | None,
    acunetix_file: str | None,
    strix_runs_dir: str | None,
    shannon_sessions_dir: str | None,
    unsw_nb15_dir: str | None,
    cic_ids_dir: str | None,
    juiceshop_traffic_dir: str | None,
    dvwa_traffic_dir: str | None,
    modsec_crs_dir: str | None,
    nvd_snapshot_file: str | None,
    commoncrawl_dir: str | None,
    max_per_category: int,
) -> list[dict]:
    records: list[dict] = []

    if payloads_dir:
        try:
            parsed = parse_payload_all_the_things(payloads_dir, max_per_category=max_per_category)
            records.extend(parsed)
            logger.info(f"   PayloadAllTheThings: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   PayloadAllTheThings skipped: {exc}")

    if seclists_dir:
        try:
            parsed = parse_seclists(seclists_dir, max_per_category=max_per_category)
            records.extend(parsed)
            logger.info(f"   SecLists: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   SecLists skipped: {exc}")

    if burp_file:
        try:
            path = Path(burp_file)
            parsed = parse_burp_xml(path) if path.suffix.lower() == ".xml" else parse_burp_json(path)
            records.extend(parsed)
            logger.info(f"   Burp: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   Burp skipped: {exc}")

    if zap_file:
        try:
            parsed = parse_zap_json(zap_file)
            records.extend(parsed)
            logger.info(f"   ZAP: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   ZAP skipped: {exc}")

    if acunetix_file:
        try:
            parsed = parse_acunetix_json(acunetix_file)
            records.extend(parsed)
            logger.info(f"   Acunetix: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   Acunetix skipped: {exc}")

    if strix_runs_dir:
        try:
            strix_path = Path(strix_runs_dir)
            if not strix_path.exists():
                raise FileNotFoundError(strix_path)
            if (strix_path / "findings").exists() or (strix_path / "proxy").exists():
                parsed = parse_strix_run(strix_path)
            else:
                parsed = parse_strix_all_runs(strix_path)
            records.extend(parsed)
            logger.info(f"   Strix snapshots: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   Strix snapshots skipped: {exc}")

    if shannon_sessions_dir:
        try:
            shannon_path = Path(shannon_sessions_dir)
            if not shannon_path.exists():
                raise FileNotFoundError(shannon_path)
            if (shannon_path / "session.json").exists():
                parsed = parse_shannon_session(shannon_path)
            else:
                parsed = parse_shannon_all_sessions(shannon_path)
            records.extend(parsed)
            logger.info(f"   Shannon snapshots: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   Shannon snapshots skipped: {exc}")

    if unsw_nb15_dir:
        try:
            parsed = parse_unsw_nb15(unsw_nb15_dir, max_rows=max(max_per_category * 100, 300_000))
            records.extend(parsed)
            logger.info(f"   UNSW-NB15: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   UNSW-NB15 skipped: {exc}")

    if cic_ids_dir:
        try:
            parsed = parse_cic_ids(cic_ids_dir, max_rows=max(max_per_category * 100, 300_000))
            records.extend(parsed)
            logger.info(f"   CIC-IDS: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   CIC-IDS skipped: {exc}")

    if juiceshop_traffic_dir:
        try:
            parsed = parse_juiceshop_traffic(
                juiceshop_traffic_dir,
                max_rows=max(max_per_category * 50, 250_000),
            )
            records.extend(parsed)
            logger.info(f"   OWASP Juice Shop traffic: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   OWASP Juice Shop traffic skipped: {exc}")

    if dvwa_traffic_dir:
        try:
            parsed = parse_dvwa_traffic(dvwa_traffic_dir, max_rows=max(max_per_category * 50, 250_000))
            records.extend(parsed)
            logger.info(f"   DVWA traffic: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   DVWA traffic skipped: {exc}")

    if modsec_crs_dir:
        try:
            parsed = parse_modsecurity_crs(modsec_crs_dir, max_rules=max(max_per_category, 3_000))
            records.extend(parsed)
            logger.info(f"   ModSecurity CRS: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   ModSecurity CRS skipped: {exc}")

    if nvd_snapshot_file:
        try:
            parsed = parse_nvd_cve_snapshot(
                nvd_snapshot_file,
                max_records=max(max_per_category * 20, 80_000),
            )
            records.extend(parsed)
            logger.info(f"   NVD/CVE snapshot: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   NVD/CVE snapshot skipped: {exc}")

    if commoncrawl_dir:
        try:
            parsed = parse_common_crawl(commoncrawl_dir, max_rows=max(max_per_category * 100, 500_000))
            records.extend(parsed)
            logger.info(f"   Common Crawl: +{len(parsed)}")
        except Exception as exc:
            logger.warning(f"   Common Crawl skipped: {exc}")

    return records


def _decorate_record(
    record: dict,
    campaign_id: str,
    target_app: str,
    lab_run_id: str,
    is_replay: bool,
) -> dict:
    payload = _safe_str(record.get("payload"))
    method = _safe_str(record.get("method"), "GET").upper()
    path = _safe_str(record.get("path"), "/")
    body = _safe_str(record.get("body"))
    src = _safe_str(record.get("source"), "unknown")
    src_file = _safe_str(record.get("source_file"), "")
    cat = _safe_str(record.get("category"), "unknown")
    sev = _safe_str(record.get("severity"), "unknown")
    evidence = _safe_str(record.get("evidence"), "")[:500]
    lbl = int(record.get("label", 1))
    validated = bool(record.get("validated", False))
    lbl_conf = float(record.get("label_confidence", 0.95 if lbl == 1 else 0.99))

    payload_hash = canonical_payload_hash(payload=payload, method=method, path=path)
    src_family = source_family(src)
    event_id = make_event_id(src, src_file, payload_hash)
    split_key = make_split_key(src_family, campaign_id, payload_hash)
    scenario_type = _safe_str(record.get("scenario_type"), _scenario_type_from_source_family(src_family))
    attack_family = _safe_str(record.get("attack_family"), cat)
    attack_technique = _safe_str(record.get("attack_technique"), cat)
    validation_tier = _safe_str(record.get("validation_tier"), _validation_tier_from_confidence(lbl_conf))
    effect_outcome = _safe_str(record.get("effect_outcome"), _effect_outcome_from_label(lbl))
    resolved_target_app = _safe_str(record.get("target_app"), target_app or "unknown")
    resolved_lab_run_id = _safe_str(record.get("lab_run_id"), lab_run_id or campaign_id)
    resolved_is_replay = bool(record.get("is_replay", is_replay))

    enriched = dict(record)
    enriched.update(
        {
            "event_id": event_id,
            "campaign_id": campaign_id,
            "source_type": src_family,
            "label": lbl,
            "label_confidence": lbl_conf,
            "validated": validated,
            "source": src,
            "source_file": src_file,
            "category": cat,
            "severity": sev,
            "evidence": evidence,
            "payload": payload,
            "method": method,
            "path": path,
            "body": body,
            "canonical_payload_hash": payload_hash,
            "source_family": src_family,
            "is_synthetic": is_synthetic_source(src),
            "split_key": split_key,
            "observed_at": _safe_str(record.get("observed_at"), now_iso()),
            "scenario_type": scenario_type,
            "target_app": resolved_target_app,
            "attack_family": attack_family,
            "attack_technique": attack_technique,
            "validation_tier": validation_tier,
            "lab_run_id": resolved_lab_run_id,
            "effect_outcome": effect_outcome,
            "is_replay": resolved_is_replay,
        }
    )
    return enriched


def build_dataset(
    payloads_dir: str | None = None,
    seclists_dir: str | None = None,
    burp_file: str | None = None,
    zap_file: str | None = None,
    acunetix_file: str | None = None,
    strix_runs_dir: str | None = None,
    shannon_sessions_dir: str | None = None,
    unsw_nb15_dir: str | None = None,
    cic_ids_dir: str | None = None,
    juiceshop_traffic_dir: str | None = None,
    dvwa_traffic_dir: str | None = None,
    modsec_crs_dir: str | None = None,
    nvd_snapshot_file: str | None = None,
    commoncrawl_dir: str | None = None,
    hard_negatives_path: str | None = None,
    hard_negative_ratio: float = 0.0,
    scenario_profile: str = "default",
    normal_count: int = 100_000,
    attack_ratio: float = 0.2,
    output: str = "./data/curated/dataset_v1.parquet",
    max_per_category: int = 5000,
    campaign_id: str = "campaign_default",
    target_app: str = "unknown",
    lab_run_id: str | None = None,
    is_replay: bool = False,
    report_path: str | None = None,
    manifest_path: str | None = None,
    strix_days: int = 0,
    strix_api_key: str | None = None,
    require_static_full: bool = False,
) -> pd.DataFrame:
    """
    Build supervised dataset (Layer 1) from local sources only.
    """
    del strix_api_key
    start = time.time()

    logger.info("=" * 70)
    logger.info("DORSAL build_dataset (local snapshot mode)")
    logger.info("=" * 70)

    if strix_days > 0:
        logger.warning(
            "--strix-days is deprecated and ignored in snapshot mode. "
            "Use --strix-runs-dir with local runs."
        )

    _validate_required_static_sources(
        require_static_full=require_static_full,
        source_paths={
            "payloads_dir": payloads_dir,
            "seclists_dir": seclists_dir,
            "unsw_nb15_dir": unsw_nb15_dir,
            "cic_ids_dir": cic_ids_dir,
            "juiceshop_traffic_dir": juiceshop_traffic_dir,
            "dvwa_traffic_dir": dvwa_traffic_dir,
            "modsec_crs_dir": modsec_crs_dir,
            "nvd_snapshot_file": nvd_snapshot_file,
            "commoncrawl_dir": commoncrawl_dir,
        },
    )

    logger.info("Collecting attack snapshots...")
    collected_records = _collect_local_attack_records(
        payloads_dir=payloads_dir,
        seclists_dir=seclists_dir,
        burp_file=burp_file,
        zap_file=zap_file,
        acunetix_file=acunetix_file,
        strix_runs_dir=strix_runs_dir,
        shannon_sessions_dir=shannon_sessions_dir,
        unsw_nb15_dir=unsw_nb15_dir,
        cic_ids_dir=cic_ids_dir,
        juiceshop_traffic_dir=juiceshop_traffic_dir,
        dvwa_traffic_dir=dvwa_traffic_dir,
        modsec_crs_dir=modsec_crs_dir,
        nvd_snapshot_file=nvd_snapshot_file,
        commoncrawl_dir=commoncrawl_dir,
        max_per_category=max_per_category,
    )
    attack_records = [row for row in collected_records if int(row.get("label", 1)) == 1]
    source_benign_records = [row for row in collected_records if int(row.get("label", 1)) == 0]
    attack_count = len(attack_records)
    logger.info(f"Collected records: total={len(collected_records):,} attack={attack_count:,} benign={len(source_benign_records):,}")

    if attack_count == 0:
        raise ValueError("No attack records collected. Provide at least one local source.")

    desired_benign = int(attack_count * (1.0 - attack_ratio) / max(attack_ratio, 1e-6))
    min_benign = max(desired_benign, normal_count)

    hard_negatives_all = _load_hard_negative_records(hard_negatives_path)
    hard_negative_n = 0
    selected_hard_negatives: list[dict] = []
    if hard_negatives_all:
        if hard_negative_ratio > 0:
            target_hard_negative = int(min_benign * hard_negative_ratio)
        else:
            target_hard_negative = min_benign
        hard_negative_n = min(target_hard_negative, len(hard_negatives_all))
        if hard_negative_n > 0:
            selected_hard_negatives = hard_negatives_all[:hard_negative_n]

    benign_remaining = max(min_benign - hard_negative_n, 0)
    source_benign_n = min(benign_remaining, len(source_benign_records))
    selected_source_benign = source_benign_records[:source_benign_n]
    normal_n = max(benign_remaining - source_benign_n, 0)
    api_types = _normal_api_types_for_profile(scenario_profile)
    logger.info(
        f"Generating synthetic normal traffic: {normal_n:,} "
        f"(hard negatives={hard_negative_n:,}, source benign={source_benign_n:,}, profile={scenario_profile})"
    )
    normals = generate_normal_requests(n=normal_n, api_types=api_types)

    all_records = attack_records + selected_hard_negatives + selected_source_benign + normals
    resolved_lab_run_id = lab_run_id or campaign_id
    all_records = [
        _decorate_record(
            record,
            campaign_id=campaign_id,
            target_app=target_app,
            lab_run_id=resolved_lab_run_id,
            is_replay=is_replay,
        )
        for record in all_records
    ]

    logger.info("Extracting features...")
    features_list: list[np.ndarray] = []
    labels: list[int] = []
    shannon_rows: list[dict[str, float]] = []

    for idx, record in enumerate(all_records, start=1):
        features = extract_features_from_payload(
            payload=record.get("payload", ""),
            method=record.get("method", "GET"),
            path=record.get("path", "/"),
            body=record.get("body", ""),
            user_agent=record.get("user_agent", ""),
            content_type=record.get("content_type", ""),
            hour_of_day=record.get("hour_of_day", 12),
            is_weekend=record.get("is_weekend", False),
            inter_request_ms=record.get("inter_request_ms", 1000.0),
        )
        features_list.append(features.to_array())
        labels.append(int(record["label"]))
        shannon_rows.append(_shannon_enrichment(record.get("payload", "")))

        if idx % 50_000 == 0:
            logger.info(f"   {idx:,}/{len(all_records):,} feature rows")

    base_feature_names = RequestFeatures.feature_names()
    X = np.asarray(features_list, dtype=np.float32)
    df = pd.DataFrame(X, columns=base_feature_names)
    df["label"] = np.asarray(labels, dtype=np.int32)

    # Canonical metadata columns
    metadata_columns = [
        "event_id",
        "campaign_id",
        "source",
        "source_type",
        "source_file",
        "source_family",
        "is_synthetic",
        "split_key",
        "canonical_payload_hash",
        "payload",
        "method",
        "path",
        "body",
        "category",
        "severity",
        "evidence",
        "validated",
        "label_confidence",
        "observed_at",
        "scenario_type",
        "target_app",
        "attack_family",
        "attack_technique",
        "validation_tier",
        "lab_run_id",
        "effect_outcome",
        "is_replay",
    ]
    for column in metadata_columns:
        df[column] = [record.get(column) for record in all_records]

    for key in shannon_rows[0].keys():
        df[key] = [row[key] for row in shannon_rows]

    before = len(df)
    df = df.drop_duplicates(subset=["canonical_payload_hash", "label"], keep="first")
    deduped = before - len(df)
    if deduped:
        logger.info(f"Removed duplicates by canonical hash: {deduped:,}")

    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)

    if report_path:
        report_out = Path(report_path)
    else:
        report_out = Path("reports") / f"dataset_build_report_{campaign_id}.json"
    report_out.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": now_iso(),
        "campaign_id": campaign_id,
        "output_path": str(out_path),
        "rows": int(len(df)),
        "feature_count": int(len(base_feature_names) + len(shannon_rows[0])),
        "attack_rows": int((df["label"] == 1).sum()),
        "normal_rows": int((df["label"] == 0).sum()),
        "hard_negative_rows": int((df["scenario_type"] == "hard_negative").sum()),
        "source_benign_rows": int(((df["label"] == 0) & (df["source_family"] != "synthetic")).sum()),
        "synthetic_normal_rows": int((df["source_family"] == "synthetic").sum()),
        "sources": df["source"].value_counts().to_dict(),
        "source_families": df["source_family"].value_counts().to_dict(),
        "categories_top": df["category"].value_counts().head(20).to_dict(),
        "scenario_types": df["scenario_type"].value_counts().to_dict(),
        "validation_tiers": df["validation_tier"].value_counts().to_dict(),
        "effect_outcomes": df["effect_outcome"].value_counts().to_dict(),
        "elapsed_seconds": round(time.time() - start, 2),
    }
    with open(report_out, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    if manifest_path:
        manifest_out = Path(manifest_path)
    else:
        manifest_out = Path("reports") / f"dataset_manifest_{campaign_id}.json"
    manifest_out.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": "2.0",
        "generated_at": now_iso(),
        "campaign_id": campaign_id,
        "target_app": target_app or "unknown",
        "lab_run_id": resolved_lab_run_id,
        "is_replay": bool(is_replay),
        "parameters": {
            "normal_count": int(normal_count),
            "attack_ratio": float(attack_ratio),
            "max_per_category": int(max_per_category),
            "hard_negative_ratio": float(hard_negative_ratio),
            "scenario_profile": scenario_profile,
        },
        "data_sources": {
            "payloads_dir": payloads_dir,
            "seclists_dir": seclists_dir,
            "burp_file": burp_file,
            "zap_file": zap_file,
            "acunetix_file": acunetix_file,
            "strix_runs_dir": strix_runs_dir,
            "shannon_sessions_dir": shannon_sessions_dir,
            "unsw_nb15_dir": unsw_nb15_dir,
            "cic_ids_dir": cic_ids_dir,
            "juiceshop_traffic_dir": juiceshop_traffic_dir,
            "dvwa_traffic_dir": dvwa_traffic_dir,
            "modsec_crs_dir": modsec_crs_dir,
            "nvd_snapshot_file": nvd_snapshot_file,
            "commoncrawl_dir": commoncrawl_dir,
            "hard_negatives_path": hard_negatives_path,
            "require_static_full": bool(require_static_full),
        },
        "artifacts": {
            "dataset_path": str(out_path),
            "report_path": str(report_out),
        },
        "distributions": {
            "labels": df["label"].value_counts().to_dict(),
            "source_families": df["source_family"].value_counts().to_dict(),
            "scenario_types": df["scenario_type"].value_counts().to_dict(),
            "validation_tiers": df["validation_tier"].value_counts().to_dict(),
            "effect_outcomes": df["effect_outcome"].value_counts().to_dict(),
            "attack_families": df["attack_family"].value_counts().head(50).to_dict(),
        },
    }
    with open(manifest_out, "w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=2)

    logger.info(f"Dataset written: {out_path}")
    logger.info(f"Build report written: {report_out}")
    logger.info(f"Build manifest written: {manifest_out}")
    logger.info(f"Elapsed: {report['elapsed_seconds']}s")
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="DORSAL build Layer-1 dataset from local snapshots")
    parser.add_argument("--payloads-dir", help="Path to PayloadAllTheThings clone")
    parser.add_argument("--seclists-dir", help="Path to SecLists clone")
    parser.add_argument("--burp-file", help="Burp export (XML/JSON)")
    parser.add_argument("--zap-file", help="ZAP report JSON")
    parser.add_argument("--acunetix-file", help="Acunetix export JSON")
    parser.add_argument("--strix-runs-dir", help="Path to Strix run dir or parent dir")
    parser.add_argument("--shannon-sessions-dir", help="Path to Shannon session dir or parent dir")
    parser.add_argument("--unsw-nb15-dir", help="Path to UNSW-NB15 local snapshot directory")
    parser.add_argument("--cic-ids-dir", help="Path to CIC-IDS 2017/2018 local snapshot directory")
    parser.add_argument("--juiceshop-traffic-dir", help="Path to OWASP Juice Shop traffic snapshots")
    parser.add_argument("--dvwa-traffic-dir", help="Path to DVWA traffic snapshots")
    parser.add_argument("--modsec-crs-dir", help="Path to ModSecurity CRS repository or exported rules")
    parser.add_argument("--nvd-snapshot-file", help="Path to NVD/CVE local snapshot JSON")
    parser.add_argument("--commoncrawl-dir", help="Path to Common Crawl sampled request files")
    parser.add_argument(
        "--hard-negatives-path",
        help="Path to hard negatives corpus (file or directory with json/jsonl/parquet)",
    )
    parser.add_argument(
        "--hard-negative-ratio",
        type=float,
        default=0.0,
        help="Target benign share from hard negatives (0 uses as many as possible when provided)",
    )
    parser.add_argument(
        "--scenario-profile",
        default="default",
        help="Synthetic normal profile: default|all|b2b|consumer|fintech|saas",
    )
    parser.add_argument("--normal-count", type=int, default=100_000)
    parser.add_argument("--attack-ratio", type=float, default=0.2)
    parser.add_argument("--max-per-category", type=int, default=5000)
    parser.add_argument("--campaign-id", default="campaign_default")
    parser.add_argument("--target-app", default="unknown")
    parser.add_argument("--lab-run-id", help="Optional lab run identifier (defaults to campaign id)")
    parser.add_argument("--is-replay", action="store_true", help="Mark samples as replay traffic")
    parser.add_argument("--output", default="./data/curated/dataset_v1.parquet")
    parser.add_argument("--report-path", help="Optional output path for JSON build report")
    parser.add_argument("--manifest-path", help="Optional output path for JSON dataset manifest")
    parser.add_argument(
        "--require-static-full",
        action="store_true",
        help="Fail when any required static source for the full profile is missing.",
    )
    parser.add_argument(
        "--strix-days",
        type=int,
        default=0,
        help="Deprecated. Kept for backwards compatibility and ignored.",
    )
    parser.add_argument("--strix-api-key", help="Deprecated and ignored.")

    args = parser.parse_args()

    # Keep parser tolerant with comma-separated directories.
    strix_runs_dir = None
    shannon_sessions_dir = None
    strix_paths = _parse_csv_dirs(args.strix_runs_dir)
    shannon_paths = _parse_csv_dirs(args.shannon_sessions_dir)
    if len(strix_paths) > 1 or len(shannon_paths) > 1:
        logger.warning(
            "Multiple snapshot dirs provided. Use one parent dir per source for deterministic builds."
        )
    if strix_paths:
        strix_runs_dir = strix_paths[0]
    if shannon_paths:
        shannon_sessions_dir = shannon_paths[0]

    build_dataset(
        payloads_dir=args.payloads_dir,
        seclists_dir=args.seclists_dir,
        burp_file=args.burp_file,
        zap_file=args.zap_file,
        acunetix_file=args.acunetix_file,
        strix_runs_dir=strix_runs_dir,
        shannon_sessions_dir=shannon_sessions_dir,
        unsw_nb15_dir=args.unsw_nb15_dir,
        cic_ids_dir=args.cic_ids_dir,
        juiceshop_traffic_dir=args.juiceshop_traffic_dir,
        dvwa_traffic_dir=args.dvwa_traffic_dir,
        modsec_crs_dir=args.modsec_crs_dir,
        nvd_snapshot_file=args.nvd_snapshot_file,
        commoncrawl_dir=args.commoncrawl_dir,
        hard_negatives_path=args.hard_negatives_path,
        hard_negative_ratio=args.hard_negative_ratio,
        scenario_profile=args.scenario_profile,
        normal_count=args.normal_count,
        attack_ratio=args.attack_ratio,
        output=args.output,
        max_per_category=args.max_per_category,
        campaign_id=args.campaign_id,
        target_app=args.target_app,
        lab_run_id=args.lab_run_id,
        is_replay=args.is_replay,
        report_path=args.report_path,
        manifest_path=args.manifest_path,
        strix_days=args.strix_days,
        strix_api_key=args.strix_api_key,
        require_static_full=args.require_static_full,
    )


if __name__ == "__main__":
    main()
