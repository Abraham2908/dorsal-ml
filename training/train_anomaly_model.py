"""
DORSAL ML Pipeline — Treino com Telemetria do Cliente (Camada 3)
=================================================================
PIPELINE 2: Dados anonimizados do gateway no cliente.

DIFERENÇA FUNDAMENTAL DOS DOIS PIPELINES:

  ┌─────────────────────────────────────────────────────────────────┐
  │ PIPELINE 1 — SEU LAB (Ryzen)                                    │
  │                                                                 │
  │ Você tem: payloads completos, requests inteiros, labels          │
  │ Algoritmo: RandomForest (supervisionado, com labels)            │
  │ Resultado: Camada 1 — Global Attack Model (ONNX)                │
  │ Já sai embarcado no container do cliente desde o dia 1           │
  └─────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────┐
  │ PIPELINE 2 — GATEWAY NO CLIENTE (este arquivo)                  │
  │                                                                 │
  │ Você NÃO recebe: payloads, IPs, paths, user-agents, bodies      │
  │ Você RECEBE: médias, desvios, contadores, hashes de endpoints    │
  │ Algoritmo: Isolation Forest (não-supervisionado, sem labels)    │
  │ Resultado: Camada 3 — Global Anomaly Model (ONNX)               │
  │                                                                 │
  │ O modelo aprende "o que é normal" estatisticamente.              │
  │ Não precisa saber o payload — só que o padrão mudou.             │
  └─────────────────────────────────────────────────────────────────┘

O QUE CHEGA DO CLIENTE (telemetria opt-in, via ClickHouse):
  - Por endpoint_hash (SHA256 do METHOD+PATH, NUNCA o path real):
    * mean(body_size), std(body_size)
    * mean(req_per_min), std(req_per_min)
    * mean(response_size), std(response_size)
    * response_time_p50, response_time_p99
  - Contadores de threats: {sqli: 23, xss: 5, bola: 8}
  - Anomaly scores médios por faixa horária
  - unique_ips, new_ips_ratio
  - error_rate_4xx, error_rate_5xx

  NUNCA: IPs reais, payloads, paths completos, user-agents, dados de usuários

POR QUE ISSO FUNCIONA SEM PAYLOADS:
  O Isolation Forest não precisa saber O QUE foi enviado.
  Ele detecta DESVIOS do padrão normal:
    - Endpoint que normalmente recebe 10 req/min agora recebe 500 → anomalia
    - Body size médio era 200 bytes, agora é 5000 → anomalia
    - Taxa de erro 4xx era 2%, agora é 40% → anomalia
    - 80% dos IPs são novos (nunca vistos) → anomalia
  
  Nenhum payload precisa sair da infra do cliente pra isso funcionar.

CRONOGRAMA:
  - Cron semanal no Ryzen: todo domingo às 02h
  - Puxa telemetria anonimizada das últimas 2 semanas
  - Treina Isolation Forest global
  - Valida FP rate
  - Se aprovado: embarca no próximo container push
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from loguru import logger

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

try:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False


# Features que vêm da telemetria anonimizada do cliente
TELEMETRY_FEATURES = [
    "total_requests",
    "body_size_mean",
    "body_size_std",
    "req_per_min_mean",
    "req_per_min_std",
    "response_size_mean",
    "response_size_std",
    "response_time_p50_ms",
    "response_time_p99_ms",
    "anomaly_score_mean",
    "anomaly_score_max",
    "unique_ips",
    "new_ips_ratio",
    "error_rate_4xx",
    "error_rate_5xx",
    "threat_count_total",
]


def prepare_telemetry_features(df: pd.DataFrame) -> tuple[np.ndarray, list[str]]:
    """
    Prepara features da telemetria para treino do Isolation Forest.
    
    O que entra: métricas agregadas anonimizadas
    O que sai: matriz de features normalizadas
    """
    df = df.copy()

    # Extrair threat_count_total se vier como dict
    if "threat_counts" in df.columns:
        df["threat_count_total"] = df["threat_counts"].apply(
            lambda x: sum(x.values()) if isinstance(x, dict) else 0
        )

    # Garantir que todas as colunas existem
    available_features = []
    for col in TELEMETRY_FEATURES:
        if col in df.columns:
            available_features.append(col)
        else:
            df[col] = 0.0
            available_features.append(col)

    X = df[available_features].fillna(0).values.astype(np.float32)

    # Substituir inf
    X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

    return X, available_features


def train_global_anomaly_model(
    telemetry_path: str | Path,
    output_path: str = "./models/anomaly_v1.onnx",
    contamination: float = 0.01,
    n_estimators: int = 200,
    max_fpr: float = 0.03,
) -> dict:
    """
    Treina o Global Anomaly Model (Camada 3) com Isolation Forest.
    
    Este modelo é NÃO-SUPERVISIONADO — não precisa de labels.
    Ele aprende o que é "normal" a partir da telemetria agregada
    e detecta desvios estatísticos.
    
    Args:
        telemetry_path: Parquet com telemetria anonimizada
        output_path: Caminho para o modelo ONNX
        contamination: Proporção esperada de anomalias (1% = conservador)
        n_estimators: Número de árvores
        max_fpr: FP rate máximo aceitável
    """
    start_time = time.time()

    logger.info("=" * 70)
    logger.info("🦈 DORSAL — Train Global Anomaly Model (Camada 3)")
    logger.info("   Pipeline 2: Telemetria anonimizada → Isolation Forest")
    logger.info("   Dados sensíveis: NENHUM (apenas métricas agregadas)")
    logger.info("=" * 70)

    # Carregar telemetria
    telemetry_path = Path(telemetry_path)
    if not telemetry_path.exists():
        logger.error(f"❌ Telemetria não encontrada: {telemetry_path}")
        return {"passed": False}

    df = pd.read_parquet(telemetry_path)
    n_tenants = df["tenant_hash"].nunique() if "tenant_hash" in df.columns else "N/A"

    logger.info(f"\n📂 Telemetria: {len(df):,} registros de {n_tenants} tenants")

    # Verificar volume mínimo
    MIN_RECORDS = 1000
    if len(df) < MIN_RECORDS:
        logger.warning(f"⚠️  Poucas amostras ({len(df)} < {MIN_RECORDS}). "
                       f"Modelo pode não ser confiável.")

    # Preparar features
    X, feature_names = prepare_telemetry_features(df)
    logger.info(f"   Features: {len(feature_names)}")

    # Normalizar (Isolation Forest se beneficia de normalização)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ============================================================
    # Treinar Isolation Forest
    # ============================================================

    logger.info(f"\n🏋️ Treinando Isolation Forest...")
    logger.info(f"   contamination={contamination} (espera {contamination*100}% anomalias)")
    logger.info(f"   n_estimators={n_estimators}")

    train_start = time.time()

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples="auto",
        n_jobs=-1,
        random_state=42,
        bootstrap=True,
    )

    model.fit(X_scaled)

    train_time = time.time() - train_start
    logger.info(f"   ✅ Treino completo em {train_time:.1f}s")

    # ============================================================
    # Avaliar
    # ============================================================

    logger.info(f"\n📊 Avaliando...")

    # Predictions: 1 = normal (inlier), -1 = anomalia (outlier)
    predictions = model.predict(X_scaled)
    scores = model.score_samples(X_scaled)

    n_anomalies = (predictions == -1).sum()
    n_normal = (predictions == 1).sum()
    anomaly_rate = n_anomalies / len(predictions)

    logger.info(f"   Normal (inlier):  {n_normal:,} ({n_normal/len(predictions)*100:.1f}%)")
    logger.info(f"   Anomalia (outlier): {n_anomalies:,} ({anomaly_rate*100:.1f}%)")
    logger.info(f"   Score range: [{scores.min():.4f}, {scores.max():.4f}]")
    logger.info(f"   Score mean: {scores.mean():.4f}, std: {scores.std():.4f}")

    # Threshold do modelo
    threshold = np.percentile(scores, contamination * 100)
    logger.info(f"   Anomaly threshold: {threshold:.4f}")

    # Validação correta: só calcula FPR quando há labels verdadeiros.
    passed = True
    eval_summary = {
        "labeled_evaluation": False,
        "fpr": None,
        "recall_anomaly": None,
    }
    label_col = None
    if "label" in df.columns:
        label_col = "label"
    elif "is_attack" in df.columns:
        label_col = "is_attack"

    if label_col is not None:
        y_true = df[label_col].astype(int).values
        y_pred = (predictions == -1).astype(int)
        tn = int(((y_true == 0) & (y_pred == 0)).sum())
        fp = int(((y_true == 0) & (y_pred == 1)).sum())
        tp = int(((y_true == 1) & (y_pred == 1)).sum())
        fn = int(((y_true == 1) & (y_pred == 0)).sum())
        fpr = fp / max(fp + tn, 1)
        recall_anomaly = tp / max(tp + fn, 1)
        eval_summary = {
            "labeled_evaluation": True,
            "label_col": label_col,
            "fpr": float(fpr),
            "recall_anomaly": float(recall_anomaly),
            "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        }
        logger.info(f"   Labeled FPR: {fpr:.4f} (target <= {max_fpr})")
        logger.info(f"   Labeled anomaly recall: {recall_anomaly:.4f}")
        if fpr > max_fpr:
            passed = False
            logger.error("   ❌ FPR excedeu o limite definido.")
    else:
        logger.info("   Sem labels verdadeiros no dataset. Pulando gate de FPR.")

    # ============================================================
    # Exportar artefato (ONNX preferencial; pickle fallback)
    # ============================================================

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    artifact_path = output
    artifact_format = "onnx"

    if ONNX_AVAILABLE:
        logger.info(f"\n📦 Exportando para ONNX: {output_path}")
        initial_type = [("input", FloatTensorType([None, X.shape[1]]))]
        try:
            onx = convert_sklearn(model, initial_types=initial_type)
            with open(output, "wb") as f:
                f.write(onx.SerializeToString())
            model_size = output.stat().st_size
            logger.info(f"   ✅ Modelo ONNX: {model_size / 1024:.1f} KB")
        except Exception as exc:
            logger.warning(
                f"   ONNX export failed ({exc.__class__.__name__}). "
                "Falling back to pickle artifact."
            )
            import pickle

            artifact_path = output.with_suffix(".pkl")
            artifact_format = "pickle"
            with open(artifact_path, "wb") as f:
                pickle.dump({"model": model, "scaler": scaler}, f)
            logger.info(f"   ✅ Modelo pickle: {artifact_path}")
    else:
        logger.warning("   ONNX runtime not available. Saving pickle artifact.")
        import pickle

        artifact_path = output.with_suffix(".pkl")
        artifact_format = "pickle"
        with open(artifact_path, "wb") as f:
            pickle.dump({"model": model, "scaler": scaler}, f)
        logger.info(f"   ✅ Modelo pickle: {artifact_path}")

    metadata = {
        "model_version": "anomaly_v1",
        "model_type": "IsolationForest",
        "pipeline": "Pipeline 2 — Telemetria Anonimizada",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "artifact_path": str(artifact_path),
        "artifact_format": artifact_format,
        "n_estimators": n_estimators,
        "contamination": contamination,
        "n_features": len(feature_names),
        "feature_names": feature_names,
        "n_samples": len(X),
        "n_tenants": str(n_tenants),
        "anomaly_rate": float(anomaly_rate),
        "score_threshold": float(threshold),
        "score_mean": float(scores.mean()),
        "score_std": float(scores.std()),
        "train_time_seconds": train_time,
        "evaluation": eval_summary,
        "scaler_mean": scaler.mean_.tolist(),
        "scaler_scale": scaler.scale_.tolist(),
        "privacy_note": (
            "Treinado exclusivamente com métricas agregadas anonimizadas. "
            "Nenhum payload, IP, path real, user-agent ou dado de "
            "usuário foi utilizado no treino."
        ),
        "data_received": [
            "média/desvio de body_size por endpoint_hash",
            "média/desvio de req_per_min",
            "contadores de threats por tipo",
            "anomaly scores médios por hora",
            "unique_ips, new_ips_ratio",
            "error_rate_4xx, error_rate_5xx",
        ],
        "data_never_received": [
            "IPs reais",
            "payloads originais",
            "paths completos",
            "user-agents",
            "bodies de requests/responses",
            "dados de usuários finais",
        ],
    }

    meta_path = output.with_suffix(".json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"   ✅ Metadados: {meta_path}")

    preproc_path = output.with_suffix(".preproc.json")
    with open(preproc_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "feature_names": feature_names,
                "scaler_mean": scaler.mean_.tolist(),
                "scaler_scale": scaler.scale_.tolist(),
            },
            f,
            indent=2,
        )
    logger.info(f"   ✅ Preprocessing: {preproc_path}")

    total_time = time.time() - start_time

    logger.info(f"\n{'=' * 70}")
    logger.info(f"✅ GLOBAL ANOMALY MODEL TREINADO")
    logger.info(f"   Tempo total: {total_time:.1f}s")
    logger.info(f"   Nenhum dado sensível utilizado.")
    logger.info(f"{'=' * 70}")

    return {
        "passed": passed,
        "anomaly_rate": float(anomaly_rate),
        "n_samples": len(X),
        "n_tenants": str(n_tenants),
        "score_threshold": float(threshold),
        "artifact_path": str(artifact_path),
        "artifact_format": artifact_format,
    }


def main():
    parser = argparse.ArgumentParser(
        description="DORSAL — Train Global Anomaly Model (Camada 3)"
    )
    parser.add_argument("--input", required=True, help="Parquet de telemetria")
    parser.add_argument("--output", default="./models/anomaly_v1.onnx")
    parser.add_argument("--contamination", type=float, default=0.01)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--max-fpr", type=float, default=0.03)

    args = parser.parse_args()

    train_global_anomaly_model(
        telemetry_path=args.input,
        output_path=args.output,
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        max_fpr=args.max_fpr,
    )


if __name__ == "__main__":
    main()
