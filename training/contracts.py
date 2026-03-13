"""Shared data contracts and canonicalization helpers for dorsal-ml."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


_WS_RE = re.compile(r"\s+")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_payload(payload: str) -> str:
    text = (payload or "").strip().lower()
    text = _WS_RE.sub(" ", text)
    return text


def normalize_path(path: str) -> str:
    text = (path or "/").strip().lower()
    return text or "/"


def canonical_payload_hash(payload: str, method: str = "GET", path: str = "/") -> str:
    base = f"{method.upper()}|{normalize_path(path)}|{normalize_payload(payload)}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def source_family(source: str) -> str:
    s = (source or "unknown").strip().lower()
    if s.startswith("synthetic_"):
        return "synthetic"
    if "payloadallthethings" in s:
        return "payload_repo"
    if "seclists" in s:
        return "payload_repo"
    if "burp" in s:
        return "dast_burp"
    if "zap" in s:
        return "dast_zap"
    if "acunetix" in s:
        return "dast_acunetix"
    if "strix" in s:
        return "agent_strix"
    if "shannon" in s:
        return "agent_shannon"
    if "gateway" in s:
        return "gateway"
    return "unknown"


def is_synthetic_source(source: str) -> bool:
    return source_family(source) == "synthetic"


def make_event_id(source: str, source_file: str, payload_hash: str) -> str:
    base = f"{source}|{source_file}|{payload_hash}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:24]


def make_split_key(
    source_family_value: str,
    campaign_id: str,
    canonical_payload_hash_value: str,
) -> str:
    return f"{source_family_value}|{campaign_id}|{canonical_payload_hash_value[:16]}"


@dataclass
class RawAttackEvent:
    event_id: str
    source: str
    source_type: str
    source_file: str
    payload: str
    method: str
    path: str
    body: str
    category: str
    severity: str
    evidence: str
    validated: bool
    label: int
    label_confidence: float
    campaign_id: str
    observed_at: str
    scenario_type: str = "unknown"
    target_app: str = "unknown"
    attack_family: str = "unknown"
    attack_technique: str = "unknown"
    validation_tier: str = "bronze"
    lab_run_id: str = "unknown"
    effect_outcome: str = "unknown"
    is_replay: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LabeledRequestSample:
    sample_id: str
    split_key: str
    source_family: str
    is_synthetic: bool
    canonical_payload_hash: str
    label: int
    label_confidence: float
    category: str
    campaign_id: str
    scenario_type: str = "unknown"
    target_app: str = "unknown"
    attack_family: str = "unknown"
    attack_technique: str = "unknown"
    validation_tier: str = "bronze"
    lab_run_id: str = "unknown"
    effect_outcome: str = "unknown"
    is_replay: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ModelArtifactManifest:
    model_version: str
    feature_names: list[str]
    feature_order: list[str]
    training_corpus_ids: list[str]
    thresholds: dict
    latency_budget_ms: float
    intended_runtime: str
    eval_summary: dict

    def to_dict(self) -> dict:
        return asdict(self)
