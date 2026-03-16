"""Train Layer-1 supervised model and export ONNX + evaluation artifacts."""

from __future__ import annotations

import argparse
import json
import pickle
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from loguru import logger
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, train_test_split

from training.contracts import ModelArtifactManifest
from training.slice_metrics import build_slice_report, evaluate_slice_gates, load_slice_gate_rules

try:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False
    logger.warning("skl2onnx not installed; ONNX export disabled")


FEATURE_COLS_BASE = [
    "requests_per_minute",
    "req_per_min_ratio",
    "hour_of_day",
    "is_weekend",
    "inter_request_ms",
    "body_size_bytes",
    "body_size_z_score",
    "param_count",
    "param_entropy",
    "url_depth",
    "url_length",
    "url_entropy",
    "user_agent_entropy",
    "content_type_mismatch",
    "ip_req_count_24h",
    "is_new_ip",
    "resource_id_sequential",
    "unique_ids_per_min",
    "has_sqli_pattern",
    "has_xss_pattern",
    "has_path_traversal",
    "has_ssrf_pattern",
    "has_ssti_pattern",
    "has_nosql_pattern",
    "response_status",
    "response_size",
    "response_size_ratio",
    "special_char_ratio",
    "payload_length",
    "payload_entropy",
]

FEATURE_COLS_SHANNON = [
    "shannon_char_entropy",
    "shannon_bigram_entropy",
    "shannon_trigram_entropy",
    "shannon_repetition",
    "shannon_alpha_ratio",
    "shannon_digit_ratio",
    "shannon_special_ratio",
    "shannon_upper_ratio",
    "shannon_url_encoded",
    "shannon_base64_likely",
]


def get_feature_cols(df: pd.DataFrame) -> list[str]:
    return [c for c in FEATURE_COLS_BASE + FEATURE_COLS_SHANNON if c in df.columns]


def _normalize_onnx_attr_value(value: object) -> object:
    if isinstance(value, (bool, np.bool_)):
        return int(value)
    if isinstance(value, np.ndarray) and value.dtype == np.bool_:
        return value.astype(np.int64)
    if isinstance(value, (list, tuple)):
        return [_normalize_onnx_attr_value(v) for v in value]
    return value


def _is_bool_attr_onnx_error(exc: BaseException) -> bool:
    cursor: BaseException | None = exc
    seen: set[int] = set()
    while cursor is not None and id(cursor) not in seen:
        seen.add(id(cursor))
        text = str(cursor)
        if "Expected an int, got a boolean" in text:
            return True
        cursor = cursor.__cause__ or cursor.__context__
    return False


def _export_onnx(model: RandomForestClassifier, n_features: int):
    initial_types = [("input", FloatTensorType([None, n_features]))]
    try:
        return convert_sklearn(model, initial_types=initial_types)
    except Exception as exc:
        # Compatibility workaround for skl2onnx/onnx stacks that emit bool attrs
        # in TreeEnsembleClassifier integer fields.
        if not _is_bool_attr_onnx_error(exc):
            raise
        import onnx.helper as onnx_helper

        logger.warning(
            "ONNX export hit bool/int attribute incompatibility; retrying with normalized attrs."
        )
        original_make_attribute = onnx_helper.make_attribute

        def _patched_make_attribute(key, value, *args, **kwargs):
            return original_make_attribute(
                key,
                _normalize_onnx_attr_value(value),
                *args,
                **kwargs,
            )

        onnx_helper.make_attribute = _patched_make_attribute
        try:
            return convert_sklearn(model, initial_types=initial_types)
        finally:
            onnx_helper.make_attribute = original_make_attribute


def _safe_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray) -> dict:
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    auc = roc_auc_score(y_true, y_score) if len(np.unique(y_true)) > 1 else 0.0
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / max(fp + tn, 1)
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "auc_roc": float(auc),
        "fpr": float(fpr),
        "confusion": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
    }


def _group_split(
    X: np.ndarray,
    y: np.ndarray,
    groups: np.ndarray | None,
    test_size: float,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    if groups is not None:
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=42)
        train_idx, test_idx = next(splitter.split(X, y, groups))
        if len(np.unique(y[train_idx])) < 2 or len(np.unique(y[test_idx])) < 2:
            logger.warning(
                "Group split produced a single-class partition; falling back to stratified random split."
            )
            train_idx, test_idx = train_test_split(
                np.arange(len(y)),
                test_size=test_size,
                stratify=y,
                random_state=42,
            )
    else:
        train_idx, test_idx = train_test_split(
            np.arange(len(y)),
            test_size=test_size,
            stratify=y,
            random_state=42,
        )

    return (
        X[train_idx],
        X[test_idx],
        y[train_idx],
        y[test_idx],
        train_idx,
        test_idx,
    )


def train_attack_model(
    dataset_path: str,
    output_path: str = "./models/attack_v1.onnx",
    n_estimators: int = 300,
    max_depth: int = 20,
    test_size: float = 0.2,
    min_precision: float = 0.92,
    min_recall: float = 0.85,
    max_fpr: float = 0.03,
    slice_min_support: int = 20,
    slice_gates_config: str | None = None,
) -> dict:
    start = time.time()
    logger.info("Loading dataset...")
    df = pd.read_parquet(dataset_path)
    feature_cols = get_feature_cols(df)
    if not feature_cols:
        raise ValueError("No usable feature columns found in dataset.")

    X = np.nan_to_num(df[feature_cols].to_numpy(dtype=np.float32), nan=0.0, posinf=1e6, neginf=-1e6)
    y = df["label"].to_numpy(dtype=np.int32)

    groups = None
    if {"source_family", "campaign_id", "canonical_payload_hash"}.issubset(df.columns):
        groups = (
            df["source_family"].astype(str)
            + "|"
            + df["campaign_id"].astype(str)
            + "|"
            + df["canonical_payload_hash"].astype(str).str[:16]
        ).to_numpy()
        logger.info("Using rigid group split by source_family+campaign_id+payload_hash.")
    else:
        logger.warning("Group split columns not found; falling back to stratified random split.")

    X_train, X_test, y_train, y_test, train_idx, test_idx = _group_split(
        X=X,
        y=y,
        groups=groups,
        test_size=test_size,
    )

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
    )
    train_start = time.time()
    model.fit(X_train, y_train)
    train_time = time.time() - train_start

    y_pred = model.predict(X_test)
    y_score = model.predict_proba(X_test)[:, 1]
    metrics = _safe_metrics(y_test, y_pred, y_score)

    # Cross-campaign/source quality checks
    slice_report = build_slice_report(
        df=df,
        y_true=y_test,
        y_pred=y_pred,
        row_indices=test_idx,
        min_support=3,
    )
    gate_rules = load_slice_gate_rules(slice_gates_config)
    slice_gate_result = evaluate_slice_gates(
        slice_report=slice_report,
        gate_rules=gate_rules,
        default_min_support=slice_min_support,
    )

    cv_mean = None
    cv_std = None
    if groups is not None and len(np.unique(groups)) >= 5:
        gkf = GroupKFold(n_splits=5)
        scores = []
        for tr, te in gkf.split(X, y, groups):
            model_cv = RandomForestClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                class_weight="balanced",
                n_jobs=-1,
                random_state=42,
                min_samples_split=5,
                min_samples_leaf=2,
                max_features="sqrt",
            )
            model_cv.fit(X[tr], y[tr])
            pred_cv = model_cv.predict(X[te])
            scores.append(f1_score(y[te], pred_cv, zero_division=0))
        cv_mean = float(np.mean(scores))
        cv_std = float(np.std(scores))

    passed = (
        metrics["precision"] >= min_precision
        and metrics["recall"] >= min_recall
        and metrics["fpr"] <= max_fpr
        and slice_gate_result["passed"]
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    if passed and ONNX_AVAILABLE:
        onx = _export_onnx(model, X.shape[1])
        with open(output, "wb") as file:
            file.write(onx.SerializeToString())
        logger.info(f"ONNX exported: {output}")
    elif not ONNX_AVAILABLE:
        logger.error("ONNX export requested but skl2onnx is unavailable.")
        passed = False

    # Always save sklearn model for parity checks.
    sk_out = output.with_suffix(".sk.pkl")
    with open(sk_out, "wb") as file:
        pickle.dump({"model": model, "feature_names": feature_cols}, file)

    eval_payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset_path": dataset_path,
        "thresholds": {
            "min_precision": min_precision,
            "min_recall": min_recall,
            "max_fpr": max_fpr,
            "slice_min_support": slice_min_support,
            "slice_gates_config": slice_gates_config,
        },
        "overall": metrics,
        "by_slice": slice_report,
        "cv_group_f1": {"mean": cv_mean, "std": cv_std},
        "slice_gates": slice_gate_result,
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "train_time_seconds": float(train_time),
        "passed": bool(passed),
        "slice_gates_passed": bool(slice_gate_result["passed"]),
    }

    features_payload = {
        "feature_order": feature_cols,
        "feature_count": len(feature_cols),
        "feature_groups": {
            "lexical": [
                "param_entropy",
                "url_entropy",
                "payload_entropy",
                "special_char_ratio",
                "shannon_char_entropy",
                "shannon_bigram_entropy",
                "shannon_trigram_entropy",
            ],
            "request_shape": [
                "param_count",
                "url_depth",
                "url_length",
                "body_size_bytes",
            ],
            "response_context": ["response_status", "response_size", "response_size_ratio"],
            "behavioral_lite": [
                "requests_per_minute",
                "req_per_min_ratio",
                "hour_of_day",
                "inter_request_ms",
                "ip_req_count_24h",
                "is_new_ip",
            ],
        },
    }

    metadata = {
        "model_version": "attack_v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "RandomForestClassifier",
        "n_estimators": n_estimators,
        "max_depth": max_depth,
        "n_features": len(feature_cols),
        "feature_names": feature_cols,
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1_score": metrics["f1"],
        "auc_roc": metrics["auc_roc"],
        "fp_rate": metrics["fpr"],
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "model_size_bytes": int(output.stat().st_size) if output.exists() else 0,
        "passed": bool(passed),
    }

    with open(output.with_suffix(".eval.json"), "w", encoding="utf-8") as file:
        json.dump(eval_payload, file, indent=2)
    with open(output.with_suffix(".features.json"), "w", encoding="utf-8") as file:
        json.dump(features_payload, file, indent=2)
    with open(output.with_suffix(".json"), "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2)

    manifest = ModelArtifactManifest(
        model_version="attack_v1",
        feature_names=feature_cols,
        feature_order=feature_cols,
        training_corpus_ids=sorted(set(df.get("campaign_id", pd.Series(["unknown"])).astype(str))),
        thresholds={
            "min_precision": min_precision,
            "min_recall": min_recall,
            "max_fpr": max_fpr,
        },
        latency_budget_ms=2.0,
        intended_runtime="gateway_client_container",
        eval_summary={
            "passed": passed,
            "slice_gates_passed": bool(slice_gate_result["passed"]),
            **metrics,
        },
    )
    with open(output.with_suffix(".manifest.json"), "w", encoding="utf-8") as file:
        json.dump(manifest.to_dict(), file, indent=2)

    logger.info(
        f"Training done in {time.time() - start:.1f}s | "
        f"precision={metrics['precision']:.4f} recall={metrics['recall']:.4f} "
        f"fpr={metrics['fpr']:.4f} passed={passed}"
    )
    return {
        "passed": bool(passed),
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "fpr": metrics["fpr"],
        "slice_gates_passed": bool(slice_gate_result["passed"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Layer-1 attack model")
    parser.add_argument("--dataset", required=True, help="Path to parquet dataset")
    parser.add_argument("--output", default="./models/attack_v1.onnx")
    parser.add_argument("--n-estimators", type=int, default=300)
    parser.add_argument("--max-depth", type=int, default=20)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--min-precision", type=float, default=0.92)
    parser.add_argument("--min-recall", type=float, default=0.85)
    parser.add_argument("--max-fpr", type=float, default=0.03)
    parser.add_argument("--slice-min-support", type=int, default=20)
    parser.add_argument("--slice-gates-config", help="JSON config path with slice gate rules")
    args = parser.parse_args()

    results = train_attack_model(
        dataset_path=args.dataset,
        output_path=args.output,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        test_size=args.test_size,
        min_precision=args.min_precision,
        min_recall=args.min_recall,
        max_fpr=args.max_fpr,
        slice_min_support=args.slice_min_support,
        slice_gates_config=args.slice_gates_config,
    )
    sys.exit(0 if results["passed"] else 1)


if __name__ == "__main__":
    main()
