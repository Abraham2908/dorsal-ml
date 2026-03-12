"""
DORSAL ML Pipeline — Parser de Telemetria do Gateway
=====================================================
Processa dados anonimizados enviados pelo container do cliente.

PRINCÍPIO DE PRIVACIDADE:
  O container do cliente NUNCA envia: IPs, payloads, paths completos,
  user-agents, dados de usuários.

  O que o container ENVIA (opt-in):
  - Distribuições estatísticas por endpoint (hash):
    média/desvio de body_size, req/min, response_size
  - Contadores de threats por tipo:
    {sqli: 23, xss: 5, bola: 8} nas últimas 24h
  - Anomaly scores médios por faixa horária
  - Hashes dos endpoints (NUNCA o path real)

COMO O GATEWAY APRENDE PADRÕES SEM DADOS SENSÍVEIS:
  ┌─────────────────────────────────────────────────────┐
  │           CONTAINER DO CLIENTE (Data Plane)          │
  │                                                      │
  │  Request → Feature Extraction → ML Inference (ONNX)  │
  │                    │                                  │
  │                    ▼                                  │
  │  ┌──────────────────────────────────────┐            │
  │  │ AGREGADOR LOCAL (SQLite)             │            │
  │  │                                      │            │
  │  │ Por cada endpoint_hash:              │            │
  │  │   - mean(body_size), std(body_size)  │            │
  │  │   - mean(req_per_min), std(...)      │            │
  │  │   - mean(response_size), std(...)    │            │
  │  │   - threat_counts: {sqli: N, ...}    │            │
  │  │   - mean(anomaly_score) por hora     │            │
  │  │   - total_requests_24h               │            │
  │  │                                      │            │
  │  │ NUNCA armazena:                      │            │
  │  │   - Payloads originais               │            │
  │  │   - IPs de origem                    │            │
  │  │   - Paths completos                  │            │
  │  │   - Headers/User-Agents              │            │
  │  └──────────────────────────────────────┘            │
  │                    │ (gRPC async, não bloqueia)       │
  │                    ▼                                  │
  └─────────────────────────────────────────────────────┘
                       │
                       ▼ (apenas métricas agregadas)
  ┌─────────────────────────────────────────────────────┐
  │           CONTROL PLANE (Dorsal — OCI)               │
  │                                                      │
  │  ClickHouse ← Telemetria anonimizada                │
  │                                                      │
  │  Cron semanal no Ryzen:                              │
  │    fetch_telemetry.py → telemetry.parquet             │
  │    train_global_anomaly.py → anomaly_vN.onnx         │
  │    validate.py → aprovado? → build container → push  │
  └─────────────────────────────────────────────────────┘

FORMATO DA TELEMETRIA (Parquet/JSON):
  Cada row = 1 endpoint_hash × 1 hora de dados
  {
    "tenant_id": "hash_do_cliente",
    "endpoint_hash": "sha256_do_METHOD+PATH",
    "window_start": "2026-03-10T14:00:00Z",
    "window_end": "2026-03-10T15:00:00Z",
    "total_requests": 1432,
    "body_size_mean": 245.3,
    "body_size_std": 89.1,
    "req_per_min_mean": 23.8,
    "req_per_min_std": 5.2,
    "response_size_mean": 1024.5,
    "response_size_std": 312.7,
    "response_time_p50_ms": 45.0,
    "response_time_p99_ms": 230.0,
    "threat_counts": {"sqli": 3, "xss": 1, "bola": 0, "rate_abuse": 2},
    "anomaly_score_mean": 0.15,
    "anomaly_score_max": 0.82,
    "unique_ips": 234,
    "new_ips_ratio": 0.12,
    "error_rate_4xx": 0.03,
    "error_rate_5xx": 0.005
  }
"""

import hashlib
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from loguru import logger


def _anonymize_endpoint(method: str, path: str) -> str:
    """
    Gera hash do endpoint — o path real NUNCA sai do container.
    Isso é feito no container do cliente, não aqui.
    """
    raw = f"{method.upper()}:{path}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _anonymize_tenant(tenant_id: str) -> str:
    """Hash do tenant para evitar correlação."""
    return hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:12]


class TelemetryRecord:
    """
    Estrutura de um registro de telemetria anonimizada.
    Cada registro = 1 endpoint × 1 janela temporal (1 hora).
    """

    __slots__ = [
        "tenant_hash", "endpoint_hash", "window_start", "window_end",
        "total_requests",
        "body_size_mean", "body_size_std",
        "req_per_min_mean", "req_per_min_std",
        "response_size_mean", "response_size_std",
        "response_time_p50_ms", "response_time_p99_ms",
        "threat_counts",
        "anomaly_score_mean", "anomaly_score_max",
        "unique_ips", "new_ips_ratio",
        "error_rate_4xx", "error_rate_5xx",
    ]

    def __init__(self, **kwargs):
        for slot in self.__slots__:
            setattr(self, slot, kwargs.get(slot, 0))

    def to_dict(self) -> dict:
        return {s: getattr(self, s) for s in self.__slots__}


def parse_telemetry_parquet(filepath: str | Path) -> pd.DataFrame:
    """
    Carrega telemetria anonimizada do Parquet (output do fetch_telemetry.py).
    
    Este arquivo é gerado pelo cron semanal que puxa dados do ClickHouse.
    Nenhum dado sensível presente — apenas métricas agregadas.
    
    Returns:
        DataFrame com features para treino do Global Anomaly Model (Camada 3)
    """
    filepath = Path(filepath)
    if not filepath.exists():
        logger.warning(f"⚠️  Telemetria não encontrada: {filepath}")
        return pd.DataFrame()

    logger.info(f"📂 Carregando telemetria: {filepath}")
    df = pd.read_parquet(filepath)

    logger.info(f"✅ Telemetria: {len(df)} registros de {df['tenant_hash'].nunique()} tenants")
    return df


def telemetry_to_anomaly_features(df: pd.DataFrame) -> np.ndarray:
    """
    Converte DataFrame de telemetria em features para o Isolation Forest global.
    
    Features usadas no Global Anomaly Model:
    - Distribuições: body_size, req_per_min, response_size (mean + std)
    - Temporal: response_time_p50, response_time_p99
    - Segurança: threat_count_total, anomaly_score_mean, anomaly_score_max
    - Rede: unique_ips, new_ips_ratio
    - Erros: error_rate_4xx, error_rate_5xx
    """
    feature_cols = [
        "total_requests",
        "body_size_mean", "body_size_std",
        "req_per_min_mean", "req_per_min_std",
        "response_size_mean", "response_size_std",
        "response_time_p50_ms", "response_time_p99_ms",
        "anomaly_score_mean", "anomaly_score_max",
        "unique_ips", "new_ips_ratio",
        "error_rate_4xx", "error_rate_5xx",
    ]

    # Extrair threat_count_total dos dicts de threat_counts
    if "threat_counts" in df.columns:
        df = df.copy()
        df["threat_count_total"] = df["threat_counts"].apply(
            lambda x: sum(x.values()) if isinstance(x, dict) else 0
        )
        feature_cols.append("threat_count_total")

    # Garantir que todas as colunas existem
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0.0

    return df[feature_cols].fillna(0).values.astype(np.float32)


def generate_synthetic_telemetry(
    n_tenants: int = 30,
    n_endpoints_per_tenant: int = 15,
    n_hours: int = 168,  # 1 semana
    attack_ratio: float = 0.02,
) -> pd.DataFrame:
    """
    Gera telemetria sintética para testes do pipeline antes de ter clientes reais.
    
    Simula padrões de tráfego normal e anômalo para validar
    o Global Anomaly Model antes de ter dados reais.
    """
    logger.info(f"🔧 Gerando telemetria sintética: {n_tenants} tenants, "
                f"{n_endpoints_per_tenant} endpoints, {n_hours}h")

    rng = np.random.default_rng(42)
    records = []

    for tenant_i in range(n_tenants):
        tenant_hash = hashlib.sha256(f"tenant_{tenant_i}".encode()).hexdigest()[:12]

        for ep_i in range(n_endpoints_per_tenant):
            endpoint_hash = hashlib.sha256(
                f"tenant_{tenant_i}_ep_{ep_i}".encode()
            ).hexdigest()[:16]

            # Baseline normal para este endpoint
            base_rpm = rng.uniform(5, 100)
            base_body = rng.uniform(50, 2000)
            base_resp = rng.uniform(200, 5000)

            for hour in range(n_hours):
                is_attack = rng.random() < attack_ratio

                if is_attack:
                    # Tráfego anômalo: spikes, body sizes estranhos
                    rpm_mult = rng.uniform(5, 50)
                    body_mult = rng.uniform(3, 20)
                    threat_count = int(rng.uniform(5, 50))
                    anomaly_score = rng.uniform(0.6, 1.0)
                else:
                    rpm_mult = rng.uniform(0.5, 2.0)
                    body_mult = rng.uniform(0.8, 1.3)
                    threat_count = int(rng.poisson(0.1))
                    anomaly_score = rng.uniform(0.0, 0.3)

                records.append({
                    "tenant_hash": tenant_hash,
                    "endpoint_hash": endpoint_hash,
                    "total_requests": int(base_rpm * 60 * rpm_mult),
                    "body_size_mean": base_body * body_mult,
                    "body_size_std": base_body * 0.3 * body_mult,
                    "req_per_min_mean": base_rpm * rpm_mult,
                    "req_per_min_std": base_rpm * 0.2,
                    "response_size_mean": base_resp,
                    "response_size_std": base_resp * 0.25,
                    "response_time_p50_ms": rng.uniform(10, 200),
                    "response_time_p99_ms": rng.uniform(100, 2000) if is_attack else rng.uniform(50, 500),
                    "threat_counts": {
                        "sqli": int(rng.poisson(threat_count * 0.3)),
                        "xss": int(rng.poisson(threat_count * 0.2)),
                        "bola": int(rng.poisson(threat_count * 0.15)),
                        "rate_abuse": int(rng.poisson(threat_count * 0.35)),
                    },
                    "anomaly_score_mean": anomaly_score,
                    "anomaly_score_max": min(anomaly_score * rng.uniform(1.0, 1.5), 1.0),
                    "unique_ips": int(rng.uniform(10, 500)),
                    "new_ips_ratio": rng.uniform(0.05, 0.4) if is_attack else rng.uniform(0.01, 0.15),
                    "error_rate_4xx": rng.uniform(0.1, 0.5) if is_attack else rng.uniform(0.01, 0.05),
                    "error_rate_5xx": rng.uniform(0.05, 0.3) if is_attack else rng.uniform(0.0, 0.01),
                })

    df = pd.DataFrame(records)
    logger.info(f"✅ Telemetria sintética: {len(df)} registros gerados")
    return df
