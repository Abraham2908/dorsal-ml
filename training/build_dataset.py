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

import numpy as np
import pandas as pd
from loguru import logger

from parsers.acunetix_parser import parse_acunetix_json
from parsers.burp_parser import parse_burp_json, parse_burp_xml
from parsers.normal_traffic_generator import generate_normal_requests
from parsers.payload_repos_parser import parse_payload_all_the_things, parse_seclists
from parsers.shannon_parser import parse_shannon_all_sessions, parse_shannon_session
from parsers.strix_parser import parse_strix_all_runs, parse_strix_run
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


def _collect_local_attack_records(
    payloads_dir: str | None,
    seclists_dir: str | None,
    burp_file: str | None,
    zap_file: str | None,
    acunetix_file: str | None,
    strix_runs_dir: str | None,
    shannon_sessions_dir: str | None,
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

    return records


def _decorate_record(record: dict, campaign_id: str) -> dict:
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
    normal_count: int = 100_000,
    attack_ratio: float = 0.2,
    output: str = "./data/curated/dataset_v1.parquet",
    max_per_category: int = 5000,
    campaign_id: str = "campaign_default",
    report_path: str | None = None,
    strix_days: int = 0,
    strix_api_key: str | None = None,
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

    logger.info("Collecting attack snapshots...")
    attacks = _collect_local_attack_records(
        payloads_dir=payloads_dir,
        seclists_dir=seclists_dir,
        burp_file=burp_file,
        zap_file=zap_file,
        acunetix_file=acunetix_file,
        strix_runs_dir=strix_runs_dir,
        shannon_sessions_dir=shannon_sessions_dir,
        max_per_category=max_per_category,
    )
    attack_count = len(attacks)
    logger.info(f"Total attack events: {attack_count:,}")

    if attack_count == 0:
        raise ValueError("No attack records collected. Provide at least one local source.")

    desired_normal = int(attack_count * (1.0 - attack_ratio) / max(attack_ratio, 1e-6))
    normal_n = max(desired_normal, normal_count)
    logger.info(f"Generating synthetic normal traffic: {normal_n:,}")
    normals = generate_normal_requests(n=normal_n)

    all_records = attacks + normals
    all_records = [_decorate_record(record, campaign_id=campaign_id) for record in all_records]

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
        "sources": df["source"].value_counts().to_dict(),
        "source_families": df["source_family"].value_counts().to_dict(),
        "categories_top": df["category"].value_counts().head(20).to_dict(),
        "elapsed_seconds": round(time.time() - start, 2),
    }
    with open(report_out, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    logger.info(f"Dataset written: {out_path}")
    logger.info(f"Build report written: {report_out}")
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
    parser.add_argument("--normal-count", type=int, default=100_000)
    parser.add_argument("--attack-ratio", type=float, default=0.2)
    parser.add_argument("--max-per-category", type=int, default=5000)
    parser.add_argument("--campaign-id", default="campaign_default")
    parser.add_argument("--output", default="./data/curated/dataset_v1.parquet")
    parser.add_argument("--report-path", help="Optional output path for JSON build report")
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
        normal_count=args.normal_count,
        attack_ratio=args.attack_ratio,
        output=args.output,
        max_per_category=args.max_per_category,
        campaign_id=args.campaign_id,
        report_path=args.report_path,
        strix_days=args.strix_days,
        strix_api_key=args.strix_api_key,
    )


if __name__ == "__main__":
    main()
