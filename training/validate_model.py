"""Validate Layer-1 ONNX artifact with global + slice-level gates."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from loguru import logger
from sklearn.metrics import confusion_matrix, precision_score, recall_score

from training.slice_metrics import build_slice_report, evaluate_slice_gates, load_slice_gate_rules

try:
    import onnxruntime as ort

    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False


EXCLUDE_NUMERIC_COLS = {
    "label",
    "payload",
    "category",
    "source",
    "shannon_z_score",
    "source_file",
    "event_id",
    "campaign_id",
    "source_type",
    "source_family",
    "split_key",
    "canonical_payload_hash",
    "method",
    "path",
    "body",
    "evidence",
    "observed_at",
    "label_confidence",
    "is_synthetic",
    "validated",
}


def _extract_predictions(raw_output: Any) -> np.ndarray:
    if isinstance(raw_output, np.ndarray):
        if raw_output.ndim == 1:
            if np.issubdtype(raw_output.dtype, np.floating):
                return (raw_output >= 0.5).astype(np.int32)
            return raw_output.astype(np.int32)
        if raw_output.ndim == 2:
            if raw_output.shape[1] == 1:
                return (raw_output[:, 0] >= 0.5).astype(np.int32)
            return np.argmax(raw_output, axis=1).astype(np.int32)
    if isinstance(raw_output, list):
        if raw_output and isinstance(raw_output[0], dict):
            probs: list[float] = []
            for row in raw_output:
                if 1 in row:
                    probs.append(float(row[1]))
                elif "1" in row:
                    probs.append(float(row["1"]))
                else:
                    probs.append(max(float(value) for value in row.values()))
            return (np.asarray(probs, dtype=np.float32) >= 0.5).astype(np.int32)
        return np.asarray(raw_output, dtype=np.int32)
    return np.asarray(raw_output, dtype=np.int32)


def _load_feature_matrix(df: pd.DataFrame, feature_cols: list[str] | None) -> tuple[np.ndarray, list[str]]:
    if feature_cols:
        X = df[feature_cols].to_numpy(dtype=np.float32)
        return X, feature_cols

    numeric_cols = [
        column
        for column in df.columns
        if column not in EXCLUDE_NUMERIC_COLS
        and df[column].dtype in [np.float32, np.float64, np.int32, np.int64]
    ]
    X = df[numeric_cols].to_numpy(dtype=np.float32)
    return X, numeric_cols


def _to_json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _to_json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_json_ready(v) for v in value]
    if isinstance(value, np.ndarray):
        return [_to_json_ready(v) for v in value.tolist()]
    if isinstance(value, np.bool_):
        return bool(value)
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, np.floating):
        return float(value)
    return value


def validate_model(
    model_path: str,
    dataset_path: str,
    min_precision: float = 0.92,
    min_recall: float = 0.85,
    max_fpr: float = 0.03,
    max_latency_p99_ms: float = 2.0,
    inference_iterations: int = 10_000,
    slice_min_support: int = 20,
    slice_gates_config: str | None = None,
    report_json: str | None = None,
) -> bool:
    logger.info("=" * 70)
    logger.info("DORSAL Layer-1 Validate Model")
    logger.info("=" * 70)

    if not ONNX_AVAILABLE:
        logger.error("onnxruntime is not installed.")
        return False

    model = Path(model_path)
    if not model.exists():
        logger.error(f"Model not found: {model}")
        return False
    logger.info(f"Model: {model} ({model.stat().st_size / 1024:.1f} KB)")

    session = ort.InferenceSession(str(model))
    input_name = session.get_inputs()[0].name
    n_features = int(session.get_inputs()[0].shape[1])

    meta_path = model.with_suffix(".json")
    feature_cols = None
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as file:
            meta = json.load(file)
        feature_cols = meta.get("feature_names")
        logger.info(f"Model version: {meta.get('model_version')}")
        logger.info(f"Created at: {meta.get('created_at')}")

    df = pd.read_parquet(dataset_path)
    X, used_features = _load_feature_matrix(df, feature_cols)
    X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
    y = df["label"].to_numpy(dtype=np.int32)

    if X.shape[1] != n_features:
        logger.error(
            f"Shape mismatch: dataset has {X.shape[1]} features, model expects {n_features}."
        )
        return False

    raw_pred = session.run(None, {input_name: X})[0]
    y_pred = _extract_predictions(raw_pred)
    if y_pred.shape[0] != y.shape[0]:
        logger.error("Prediction size mismatch with labels.")
        return False

    precision = precision_score(y, y_pred, zero_division=0)
    recall = recall_score(y, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
    fpr = fp / max(fp + tn, 1)

    global_results = {
        "precision": {
            "value": float(precision),
            "target": float(min_precision),
            "passed": bool(precision >= min_precision),
        },
        "recall": {
            "value": float(recall),
            "target": float(min_recall),
            "passed": bool(recall >= min_recall),
        },
        "fpr": {"value": float(fpr), "target": float(max_fpr), "passed": bool(fpr <= max_fpr)},
        "confusion": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
    }

    logger.info("Global metrics")
    logger.info(
        f"  precision={precision:.4f} (target>={min_precision:.4f}) "
        f"recall={recall:.4f} (target>={min_recall:.4f}) "
        f"fpr={fpr:.4f} (target<={max_fpr:.4f})"
    )

    sample = X[:1].astype(np.float32)
    for _ in range(100):
        session.run(None, {input_name: sample})

    latencies: list[float] = []
    for i in range(inference_iterations):
        idx = i % len(X)
        one = X[idx : idx + 1].astype(np.float32)
        t0 = time.perf_counter_ns()
        session.run(None, {input_name: one})
        t1 = time.perf_counter_ns()
        latencies.append((t1 - t0) / 1_000_000)

    latency_arr = np.asarray(latencies, dtype=np.float64)
    p50 = float(np.percentile(latency_arr, 50))
    p95 = float(np.percentile(latency_arr, 95))
    p99 = float(np.percentile(latency_arr, 99))
    mean_lat = float(np.mean(latency_arr))
    latency_ok = p99 <= max_latency_p99_ms

    logger.info(
        f"Latency mean={mean_lat:.3f}ms p50={p50:.3f}ms p95={p95:.3f}ms "
        f"p99={p99:.3f}ms (target<={max_latency_p99_ms:.3f}ms)"
    )

    slice_report = build_slice_report(
        df=df,
        y_true=y,
        y_pred=y_pred,
        row_indices=np.arange(len(df)),
        min_support=3,
    )
    gate_rules = load_slice_gate_rules(slice_gates_config)
    slice_gate_result = evaluate_slice_gates(
        slice_report=slice_report,
        gate_rules=gate_rules,
        default_min_support=slice_min_support,
    )
    if slice_gate_result["enabled"]:
        logger.info(
            f"Slice gates enabled: rules={slice_gate_result['rules_evaluated']} "
            f"passed={slice_gate_result['passed']}"
        )

    passed = (
        global_results["precision"]["passed"]
        and global_results["recall"]["passed"]
        and global_results["fpr"]["passed"]
        and latency_ok
        and slice_gate_result["passed"]
    )

    report = {
        "model_path": str(model),
        "dataset_path": dataset_path,
        "used_feature_count": len(used_features),
        "used_features": used_features,
        "thresholds": {
            "min_precision": min_precision,
            "min_recall": min_recall,
            "max_fpr": max_fpr,
            "max_latency_p99_ms": max_latency_p99_ms,
            "slice_min_support": slice_min_support,
            "slice_gates_config": slice_gates_config,
        },
        "overall": {
            "precision": float(precision),
            "recall": float(recall),
            "fpr": float(fpr),
            "confusion": global_results["confusion"],
        },
        "global_gates": global_results,
        "latency": {
            "mean_ms": mean_lat,
            "p50_ms": p50,
            "p95_ms": p95,
            "p99_ms": p99,
            "passed": bool(latency_ok),
            "target_p99_ms": max_latency_p99_ms,
        },
        "by_slice": slice_report,
        "slice_gates": slice_gate_result,
        "passed": bool(passed),
    }

    report_path = Path(report_json) if report_json else model.with_suffix(".validation.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(_to_json_ready(report), file, indent=2)
    logger.info(f"Validation report written: {report_path}")

    if passed:
        logger.info("MODEL APPROVED")
    else:
        logger.error("MODEL REJECTED")
        if not global_results["precision"]["passed"]:
            logger.error("  precision gate failed")
        if not global_results["recall"]["passed"]:
            logger.error("  recall gate failed")
        if not global_results["fpr"]["passed"]:
            logger.error("  fpr gate failed")
        if not latency_ok:
            logger.error("  latency gate failed")
        if not slice_gate_result["passed"]:
            logger.error("  slice gates failed")

    return passed


def main() -> None:
    parser = argparse.ArgumentParser(description="DORSAL Layer-1 model validation")
    parser.add_argument("--model", required=True, help="Path to ONNX model")
    parser.add_argument("--dataset", required=True, help="Path to dataset parquet")
    parser.add_argument("--min-precision", type=float, default=0.92)
    parser.add_argument("--min-recall", type=float, default=0.85)
    parser.add_argument("--max-fpr", type=float, default=0.03)
    parser.add_argument("--max-latency-p99", type=float, default=2.0)
    parser.add_argument("--iterations", type=int, default=10_000)
    parser.add_argument("--slice-min-support", type=int, default=20)
    parser.add_argument("--slice-gates-config", help="JSON config path with slice gate rules")
    parser.add_argument("--report-json", help="Optional output JSON path for validation report")
    args = parser.parse_args()

    ok = validate_model(
        model_path=args.model,
        dataset_path=args.dataset,
        min_precision=args.min_precision,
        min_recall=args.min_recall,
        max_fpr=args.max_fpr,
        max_latency_p99_ms=args.max_latency_p99,
        inference_iterations=args.iterations,
        slice_min_support=args.slice_min_support,
        slice_gates_config=args.slice_gates_config,
        report_json=args.report_json,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
