"""
DORSAL ML Pipeline — Feature Extraction Engine
================================================
Extrai as 20+ features de cada request para alimentar os modelos.
Todas as features são numéricas e normalizáveis.

Referência: dorsal_ml_arquitetura.docx — Seção 3.3
"""

import re
import math
import hashlib
from typing import Optional
from dataclasses import dataclass, field, asdict

import numpy as np


# ============================================================
# Regex patterns pré-compilados (performance crítica)
# ============================================================

SQLI_PATTERNS = [
    re.compile(r"(\b(union|select|insert|update|delete|drop|alter|create|exec)\b\s)", re.I),
    re.compile(r"('|\")(\s)*(or|and)(\s)+(.*?)(=|>|<)", re.I),
    re.compile(r"(\b(sleep|benchmark|waitfor|delay|pg_sleep)\b\s*\()", re.I),
    re.compile(r"(--|#|/\*)", re.I),
    re.compile(r"(\b(char|nchar|varchar|concat|group_concat|load_file|into\s+outfile)\b)", re.I),
    re.compile(r"(0x[0-9a-fA-F]+)", re.I),
    re.compile(r"(\binformation_schema\b)", re.I),
]

XSS_PATTERNS = [
    re.compile(r"<\s*script[^>]*>", re.I),
    re.compile(r"on\w+\s*=\s*['\"]", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"<\s*img[^>]+onerror", re.I),
    re.compile(r"<\s*svg[^>]+onload", re.I),
    re.compile(r"(document\.(cookie|location|write)|window\.(location|open))", re.I),
    re.compile(r"<\s*iframe", re.I),
    re.compile(r"eval\s*\(", re.I),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./", re.I),
    re.compile(r"\.\.\\", re.I),
    re.compile(r"%2e%2e[/%5c]", re.I),
    re.compile(r"\.\./etc/passwd", re.I),
    re.compile(r"(proc/self|/dev/null|boot\.ini)", re.I),
    re.compile(r"%00", re.I),  # null byte
]

SSRF_PATTERNS = [
    re.compile(r"(169\.254\.\d+\.\d+)", re.I),  # AWS metadata
    re.compile(r"(127\.0\.0\.1|localhost|0\.0\.0\.0)", re.I),
    re.compile(r"(10\.\d+\.\d+\.\d+)", re.I),
    re.compile(r"(172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)", re.I),
    re.compile(r"(192\.168\.\d+\.\d+)", re.I),
    re.compile(r"(file://|gopher://|dict://|ftp://)", re.I),
    re.compile(r"(metadata\.google\.internal)", re.I),
]

SSTI_PATTERNS = [
    re.compile(r"\{\{.*?\}\}", re.I),        # Jinja2/Twig
    re.compile(r"\$\{.*?\}", re.I),           # Java EL
    re.compile(r"#\{.*?\}", re.I),            # Ruby/Freemarker
    re.compile(r"<%= .*? %>", re.I),          # ERB
    re.compile(r"(__class__|__mro__|__subclasses__|__builtins__)", re.I),
]

NOSQL_PATTERNS = [
    re.compile(r"\$((ne|gt|lt|gte|lte|nin|in|regex|where|exists))\b", re.I),
    re.compile(r"\{.*?\$.*?\}", re.I),
    re.compile(r"(db\.|collection\.|find\(|aggregate\()", re.I),
]


def _score_patterns(text: str, patterns: list[re.Pattern]) -> float:
    """Retorna score 0.0–1.0 baseado em quantos patterns matcham."""
    if not text:
        return 0.0
    matches = sum(1 for p in patterns if p.search(text))
    return min(matches / max(len(patterns) * 0.3, 1), 1.0)


def shannon_entropy(text: str) -> float:
    """Calcula entropia de Shannon do texto (bits por caractere)."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _count_special_chars(text: str) -> int:
    """Conta caracteres especiais (não alfanuméricos, não espaço)."""
    return sum(1 for c in text if not c.isalnum() and c != ' ')


def _url_depth(path: str) -> int:
    """Conta profundidade do path da URL."""
    return len([s for s in path.split('/') if s])


@dataclass
class RequestFeatures:
    """
    Vetor de features extraído de uma única request HTTP.
    Todas as 20+ features documentadas na arquitetura do Dorsal.
    """
    # === Rate/Temporal ===
    requests_per_minute: float = 0.0
    req_per_min_ratio: float = 1.0
    hour_of_day: int = 12
    is_weekend: bool = False
    inter_request_ms: float = 1000.0

    # === Body/Size ===
    body_size_bytes: float = 0.0
    body_size_z_score: float = 0.0

    # === Parameters ===
    param_count: int = 0
    param_entropy: float = 0.0

    # === URL ===
    url_depth: int = 0
    url_length: int = 0
    url_entropy: float = 0.0

    # === Headers ===
    user_agent_entropy: float = 0.0
    content_type_mismatch: bool = False

    # === IP/Network ===
    ip_req_count_24h: int = 0
    is_new_ip: bool = False

    # === Resource IDs (BOLA/IDOR) ===
    resource_id_sequential: float = 0.0
    unique_ids_per_min: int = 0

    # === Attack Patterns (scores 0-1) ===
    has_sqli_pattern: float = 0.0
    has_xss_pattern: float = 0.0
    has_path_traversal: float = 0.0
    has_ssrf_pattern: float = 0.0
    has_ssti_pattern: float = 0.0
    has_nosql_pattern: float = 0.0

    # === Response (quando disponível) ===
    response_status: int = 200
    response_size: float = 0.0
    response_size_ratio: float = 1.0

    # === Payload-level ===
    special_char_ratio: float = 0.0
    payload_length: int = 0
    payload_entropy: float = 0.0

    def to_array(self) -> np.ndarray:
        """Converte para array NumPy para inferência."""
        d = asdict(self)
        # Converte bools para float
        for k, v in d.items():
            if isinstance(v, bool):
                d[k] = float(v)
        return np.array(list(d.values()), dtype=np.float32)

    @staticmethod
    def feature_names() -> list[str]:
        """Nomes das features na ordem do array."""
        return list(RequestFeatures().__dataclass_fields__.keys())

    @staticmethod
    def feature_count() -> int:
        return len(RequestFeatures.__dataclass_fields__)


def extract_features_from_payload(
    payload: str,
    method: str = "GET",
    path: str = "/",
    body: str = "",
    user_agent: str = "",
    content_type: str = "",
    # Contexto temporal (para requests reais, preenchido pelo gateway)
    requests_per_minute: float = 0.0,
    req_per_min_ratio: float = 1.0,
    hour_of_day: int = 12,
    is_weekend: bool = False,
    inter_request_ms: float = 1000.0,
    ip_req_count_24h: int = 0,
    is_new_ip: bool = False,
    resource_id_sequential: float = 0.0,
    unique_ids_per_min: int = 0,
    response_status: int = 200,
    response_size: float = 0.0,
    response_size_ratio: float = 1.0,
    body_size_z_score: float = 0.0,
) -> RequestFeatures:
    """
    Extrai features de uma request (ou de um payload isolado para treino).
    
    Para treino com payloads brutos (PayloadAllTheThings, SecLists):
        - payload = o texto do payload
        - Demais campos usam defaults ou são sintéticos
    
    Para requests reais (Burp, ZAP, Gateway):
        - Todos os campos são preenchidos com dados reais
    """
    # Texto completo para análise de patterns
    full_text = f"{path} {payload} {body}"

    features = RequestFeatures(
        # Rate/Temporal
        requests_per_minute=requests_per_minute,
        req_per_min_ratio=req_per_min_ratio,
        hour_of_day=hour_of_day,
        is_weekend=is_weekend,
        inter_request_ms=inter_request_ms,

        # Body/Size
        body_size_bytes=float(len(body.encode('utf-8', errors='replace'))),
        body_size_z_score=body_size_z_score,

        # Parameters
        param_count=full_text.count('=') + full_text.count('&'),
        param_entropy=shannon_entropy(
            '&'.join(p.split('=', 1)[-1] for p in full_text.split('&') if '=' in p)
        ),

        # URL
        url_depth=_url_depth(path),
        url_length=len(path),
        url_entropy=shannon_entropy(path),

        # Headers
        user_agent_entropy=shannon_entropy(user_agent),
        content_type_mismatch=(
            content_type != "" and
            method in ("POST", "PUT", "PATCH") and
            "json" not in content_type.lower() and
            "form" not in content_type.lower()
        ),

        # IP/Network
        ip_req_count_24h=ip_req_count_24h,
        is_new_ip=is_new_ip,

        # Resource IDs
        resource_id_sequential=resource_id_sequential,
        unique_ids_per_min=unique_ids_per_min,

        # Attack Patterns
        has_sqli_pattern=_score_patterns(full_text, SQLI_PATTERNS),
        has_xss_pattern=_score_patterns(full_text, XSS_PATTERNS),
        has_path_traversal=_score_patterns(full_text, PATH_TRAVERSAL_PATTERNS),
        has_ssrf_pattern=_score_patterns(full_text, SSRF_PATTERNS),
        has_ssti_pattern=_score_patterns(full_text, SSTI_PATTERNS),
        has_nosql_pattern=_score_patterns(full_text, NOSQL_PATTERNS),

        # Response
        response_status=response_status,
        response_size=response_size,
        response_size_ratio=response_size_ratio,

        # Payload-level
        special_char_ratio=(
            _count_special_chars(payload) / max(len(payload), 1)
        ),
        payload_length=len(payload),
        payload_entropy=shannon_entropy(payload),
    )

    return features
