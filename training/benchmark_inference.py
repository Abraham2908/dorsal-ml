"""Benchmark ONNX inference latency and parity against sklearn (when available)."""

from __future__ import annotations

import argparse
import json
import pickle
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort
import pandas as pd
from loguru import logger


def _extract_onnx_probabilities(raw_output: object) -> np.ndarray | None:
    # Common with skl2onnx zipmap=False: ndarray shape (n, classes)
    if isinstance(raw_output, np.ndarray):
        if raw_output.ndim == 2 and raw_output.shape[1] >= 2:
            return raw_output[:, 1]
        return None
    # Common with zipmap=True: list[dict[int|str,float]]
    if isinstance(raw_output, list) and raw_output and isinstance(raw_output[0], dict):
        values = []
        for row in raw_output:
            if 1 in row:
                values.append(float(row[1]))
            elif "1" in row:
                values.append(float(row["1"]))
            else:
                values.append(max(float(v) for v in row.values()))
        return np.asarray(values, dtype=np.float32)
    return None


def _load_feature_matrix(dataset_path: str, feature_names: list[str] | None) -> np.ndarray:
    df = pd.read_parquet(dataset_path)
    if feature_names:
        X = df[feature_names].to_numpy(dtype=np.float32)
    else:
        excluded = {
            "label",
            "payload",
            "category",
            "source",
            "source_file",
            "event_id",
            "campaign_id",
            "source_type",
            "source_family",
            "split_key",
            "canonical_payload_hash",
            "evidence",
            "body",
            "path",
            "method",
            "observed_at",
        }
        cols = [
            c
            for c in df.columns
            if c not in excluded and pd.api.types.is_numeric_dtype(df[c].dtype)
        ]
        X = df[cols].to_numpy(dtype=np.float32)
    return np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6).astype(np.float32)


def _latency_stats(latencies_ms: np.ndarray) -> dict:
    return {
        "mean_ms": float(np.mean(latencies_ms)),
        "p50_ms": float(np.percentile(latencies_ms, 50)),
        "p95_ms": float(np.percentile(latencies_ms, 95)),
        "p99_ms": float(np.percentile(latencies_ms, 99)),
    }


def benchmark(
    model_path: str,
    dataset_path: str,
    iterations: int = 10_000,
    batch_sizes: tuple[int, int] = (1, 32),
    sklearn_pickle_path: str | None = None,
    output_json: str | None = None,
) -> dict:
    model = Path(model_path)
    meta_path = model.with_suffix(".json")
    features_path = model.with_suffix(".features.json")
    feature_names = None

    if Path(features_path).exists():
        with open(features_path, "r", encoding="utf-8") as file:
            feature_names = json.load(file).get("feature_order")
    elif meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as file:
            feature_names = json.load(file).get("feature_names")

    X = _load_feature_matrix(dataset_path, feature_names)
    if len(X) == 0:
        raise ValueError("Dataset is empty.")

    session = ort.InferenceSession(str(model))
    input_name = session.get_inputs()[0].name
    output_names = [out.name for out in session.get_outputs()]
    logger.info(f"ONNX outputs: {output_names}")

    # Warmup
    sample = X[:1]
    for _ in range(200):
        session.run(None, {input_name: sample})

    latency = {}
    for batch in batch_sizes:
        latencies = []
        for i in range(iterations):
            idx = i % len(X)
            batch_x = X[idx : idx + batch]
            if len(batch_x) < batch:
                pad = batch - len(batch_x)
                batch_x = np.concatenate([batch_x, X[:pad]], axis=0)
            t0 = time.perf_counter_ns()
            session.run(None, {input_name: batch_x})
            t1 = time.perf_counter_ns()
            latencies.append((t1 - t0) / 1_000_000.0)
        latency[f"batch_{batch}"] = _latency_stats(np.asarray(latencies, dtype=np.float64))

    parity = {"available": False}
    if sklearn_pickle_path is None:
        candidate = model.with_suffix(".sk.pkl")
        if candidate.exists():
            sklearn_pickle_path = str(candidate)

    if sklearn_pickle_path and Path(sklearn_pickle_path).exists():
        with open(sklearn_pickle_path, "rb") as file:
            payload = pickle.load(file)
        sk_model = payload["model"] if isinstance(payload, dict) and "model" in payload else payload
        sk_probs = sk_model.predict_proba(X[: min(5000, len(X))])[:, 1]
        onnx_outs = session.run(None, {input_name: X[: min(5000, len(X))]})
        onnx_probs = None
        for out in onnx_outs:
            onnx_probs = _extract_onnx_probabilities(out)
            if onnx_probs is not None:
                break

        if onnx_probs is not None:
            delta = np.abs(sk_probs - onnx_probs)
            parity = {
                "available": True,
                "n_samples": int(len(delta)),
                "max_abs_delta": float(np.max(delta)),
                "mean_abs_delta": float(np.mean(delta)),
                "p99_abs_delta": float(np.percentile(delta, 99)),
            }
        else:
            parity = {
                "available": False,
                "reason": "ONNX probabilities not available in exported graph.",
            }

    result = {
        "model_path": str(model),
        "dataset_path": dataset_path,
        "iterations": iterations,
        "latency": latency,
        "parity": parity,
    }
    if output_json:
        output = Path(output_json)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as file:
            json.dump(result, file, indent=2)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark ONNX latency and sklearn parity")
    parser.add_argument("--model", required=True, help="Path to ONNX model")
    parser.add_argument("--dataset", required=True, help="Dataset parquet for benchmark rows")
    parser.add_argument("--iterations", type=int, default=10_000)
    parser.add_argument(
        "--sklearn-pickle",
        help="Optional sklearn pickle path (defaults to model basename + .sk.pkl when present)",
    )
    parser.add_argument("--output-json", help="Optional JSON output path")
    args = parser.parse_args()

    result = benchmark(
        model_path=args.model,
        dataset_path=args.dataset,
        iterations=args.iterations,
        sklearn_pickle_path=args.sklearn_pickle,
        output_json=args.output_json,
    )
    logger.info(
        f"batch_1 p99: {result['latency']['batch_1']['p99_ms']:.4f}ms | "
        f"batch_32 p99: {result['latency']['batch_32']['p99_ms']:.4f}ms"
    )
    if result["parity"].get("available"):
        logger.info(f"parity max_abs_delta: {result['parity']['max_abs_delta']:.6f}")


if __name__ == "__main__":
    main()
