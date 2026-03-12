"""
DORSAL ML Pipeline — Validate Model (Passo 5 do Pipeline)
============================================================
Valida modelo ONNX contra critérios obrigatórios antes de embutir no container.

Critérios obrigatórios:
  - Precision > 90%
  - Recall > 85%
  - FP Rate < 5%
  - Inferência P99 < 2ms (com ONNX runtime)

USO:
  python -m training.validate_model \
    --model ./models/attack_v1.onnx \
    --dataset ./data/dataset_v1.parquet \
    --min-precision 0.90 \
    --max-fpr 0.05
"""

import argparse
import sys
import time
import json
from pathlib import Path

import numpy as np
import pandas as pd
from loguru import logger

try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False

from sklearn.metrics import precision_score, recall_score, confusion_matrix


def validate_model(
    model_path: str,
    dataset_path: str,
    min_precision: float = 0.92,
    min_recall: float = 0.85,
    max_fpr: float = 0.03,
    max_latency_p99_ms: float = 2.0,
    inference_iterations: int = 10_000,
) -> bool:
    """
    Validação completa do modelo ONNX.
    
    Returns:
        True se o modelo passou em todos os critérios
    """
    logger.info("=" * 70)
    logger.info("🦈 DORSAL ML Pipeline — Validate Model")
    logger.info("=" * 70)

    if not ONNX_AVAILABLE:
        logger.error("❌ onnxruntime não instalado!")
        return False

    # Carregar modelo
    model_path = Path(model_path)
    if not model_path.exists():
        logger.error(f"❌ Modelo não encontrado: {model_path}")
        return False

    logger.info(f"📂 Modelo: {model_path} ({model_path.stat().st_size / 1024:.1f} KB)")

    session = ort.InferenceSession(str(model_path))
    input_name = session.get_inputs()[0].name
    n_features = session.get_inputs()[0].shape[1]
    logger.info(f"   Features esperadas: {n_features}")

    # Carregar metadados se existem
    meta_path = model_path.with_suffix(".json")
    feature_cols = None
    if meta_path.exists():
        with open(meta_path) as f:
            meta = json.load(f)
        feature_cols = meta.get("feature_names")
        logger.info(f"   Versão: {meta.get('model_version')}")
        logger.info(f"   Criado: {meta.get('created_at')}")

    # Carregar dataset
    logger.info(f"\n📂 Dataset: {dataset_path}")
    df = pd.read_parquet(dataset_path)

    if feature_cols:
        X = df[feature_cols].values.astype(np.float32)
    else:
        # Fallback: usar todas as colunas numéricas menos label/metadata
        exclude = [
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
        ]
        num_cols = [c for c in df.columns if c not in exclude and df[c].dtype in [np.float32, np.float64, np.int32, np.int64]]
        X = df[num_cols].values.astype(np.float32)

    X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
    y = df["label"].values

    # Garantir shape correto
    if X.shape[1] != n_features:
        logger.error(f"❌ Shape mismatch: dataset tem {X.shape[1]} features, modelo espera {n_features}")
        return False

    # ============================================================
    # Teste 1: Métricas de classificação
    # ============================================================

    logger.info("\n📊 Teste 1: Métricas de classificação...")

    y_pred = session.run(None, {input_name: X})[0]

    precision = precision_score(y, y_pred)
    recall = recall_score(y, y_pred)
    tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
    fpr = fp / (fp + tn)

    results = {}
    all_passed = True

    # Precision
    p_ok = precision >= min_precision
    results["precision"] = {"value": precision, "target": min_precision, "passed": p_ok}
    logger.info(f"   {'✅' if p_ok else '❌'} Precision: {precision:.4f} (target: >={min_precision})")
    if not p_ok:
        all_passed = False

    # Recall
    r_ok = recall >= min_recall
    results["recall"] = {"value": recall, "target": min_recall, "passed": r_ok}
    logger.info(f"   {'✅' if r_ok else '❌'} Recall: {recall:.4f} (target: >={min_recall})")
    if not r_ok:
        all_passed = False

    # FP Rate
    f_ok = fpr <= max_fpr
    results["fpr"] = {"value": fpr, "target": max_fpr, "passed": f_ok}
    logger.info(f"   {'✅' if f_ok else '❌'} FP Rate: {fpr:.4f} (target: <={max_fpr})")
    if not f_ok:
        all_passed = False

    # ============================================================
    # Teste 2: Benchmark de latência
    # ============================================================

    logger.info(f"\n⚡ Teste 2: Benchmark de latência ({inference_iterations:,} iterações)...")

    # Warm up
    sample = X[:1].astype(np.float32)
    for _ in range(100):
        session.run(None, {input_name: sample})

    # Benchmark
    latencies = []
    for i in range(inference_iterations):
        idx = i % len(X)
        sample = X[idx:idx+1].astype(np.float32)

        t0 = time.perf_counter_ns()
        session.run(None, {input_name: sample})
        t1 = time.perf_counter_ns()

        latencies.append((t1 - t0) / 1_000_000)  # ns → ms

    latencies = np.array(latencies)
    p50 = np.percentile(latencies, 50)
    p95 = np.percentile(latencies, 95)
    p99 = np.percentile(latencies, 99)
    mean_lat = np.mean(latencies)

    l_ok = p99 <= max_latency_p99_ms
    results["latency_p99"] = {"value": p99, "target": max_latency_p99_ms, "passed": l_ok}

    logger.info(f"   Mean: {mean_lat:.3f}ms")
    logger.info(f"   P50:  {p50:.3f}ms")
    logger.info(f"   P95:  {p95:.3f}ms")
    logger.info(f"   {'✅' if l_ok else '❌'} P99:  {p99:.3f}ms (target: <={max_latency_p99_ms}ms)")
    if not l_ok:
        all_passed = False

    # ============================================================
    # Resultado final
    # ============================================================

    logger.info(f"\n{'=' * 70}")
    if all_passed:
        logger.info("✅ MODELO APROVADO — Pronto para embutir no container!")
        logger.info(f"   Copiar: cp {model_path} gateway/dorsal/ml/models/")
    else:
        logger.error("❌ MODELO REPROVADO — Critérios não atingidos.")
        for name, result in results.items():
            if not result["passed"]:
                logger.error(f"   FALHOU: {name} = {result['value']:.4f} (target: {result['target']})")
    logger.info(f"{'=' * 70}")

    return all_passed


def main():
    parser = argparse.ArgumentParser(description="DORSAL — Validate Model")
    parser.add_argument("--model", required=True, help="Path do modelo ONNX")
    parser.add_argument("--dataset", required=True, help="Path do dataset")
    parser.add_argument("--min-precision", type=float, default=0.92)
    parser.add_argument("--min-recall", type=float, default=0.85)
    parser.add_argument("--max-fpr", type=float, default=0.03)
    parser.add_argument("--max-latency-p99", type=float, default=2.0)
    parser.add_argument("--iterations", type=int, default=10000)

    args = parser.parse_args()

    passed = validate_model(
        model_path=args.model,
        dataset_path=args.dataset,
        min_precision=args.min_precision,
        min_recall=args.min_recall,
        max_fpr=args.max_fpr,
        max_latency_p99_ms=args.max_latency_p99,
        inference_iterations=args.iterations,
    )

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
