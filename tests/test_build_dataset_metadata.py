from __future__ import annotations

import json

import numpy as np
import pandas as pd

import training.build_dataset as build_dataset_mod


def test_metadata_helpers_defaults() -> None:
    assert build_dataset_mod._scenario_type_from_source_family("payload_repo") == "public_payload"
    assert build_dataset_mod._scenario_type_from_source_family("dast_zap") == "scanner_dast"
    assert build_dataset_mod._scenario_type_from_source_family("agent_strix") == "agent_attack"
    assert build_dataset_mod._scenario_type_from_source_family("synthetic") == "legit_background"
    assert build_dataset_mod._scenario_type_from_source_family("public_flow") == "public_flow_dataset"
    assert build_dataset_mod._scenario_type_from_source_family("public_benign") == "public_benign_dataset"
    assert build_dataset_mod._scenario_type_from_source_family("vuln_feed") == "vuln_intel_seed"
    assert build_dataset_mod._scenario_type_from_source_family("waf_rules") == "waf_rule_seed"
    assert build_dataset_mod._scenario_type_from_source_family("unknown") == "unknown"

    assert build_dataset_mod._validation_tier_from_confidence(0.95) == "gold"
    assert build_dataset_mod._validation_tier_from_confidence(0.82) == "silver"
    assert build_dataset_mod._validation_tier_from_confidence(0.50) == "bronze"

    assert build_dataset_mod._effect_outcome_from_label(1) == "attempt_only"
    assert build_dataset_mod._effect_outcome_from_label(0) == "unknown"


def test_build_dataset_writes_new_metadata_and_manifest(monkeypatch, tmp_path) -> None:
    attacks = [
        {
            "payload": "' OR 1=1 --",
            "method": "GET",
            "path": "/api/login",
            "body": "",
            "source": "PayloadAllTheThings",
            "source_file": "sqli.txt",
            "category": "sqli",
            "severity": "high",
            "label": 1,
            "label_confidence": 0.97,
        }
    ]
    normals = [
        {
            "payload": "john@example.com",
            "method": "POST",
            "path": "/api/login",
            "body": '{"email":"john@example.com"}',
            "source": "synthetic_saas_b2b",
            "category": "normal",
            "label": 0,
            "label_confidence": 0.99,
        }
    ]

    class _DummyFeatures:
        def to_array(self) -> np.ndarray:
            size = len(build_dataset_mod.RequestFeatures.feature_names())
            return np.zeros(size, dtype=np.float32)

    monkeypatch.setattr(build_dataset_mod, "_collect_local_attack_records", lambda **kwargs: attacks)
    monkeypatch.setattr(
        build_dataset_mod,
        "generate_normal_requests",
        lambda n, api_types=None: normals,
    )
    monkeypatch.setattr(build_dataset_mod, "extract_features_from_payload", lambda **kwargs: _DummyFeatures())

    dataset_path = tmp_path / "dataset.parquet"
    report_path = tmp_path / "dataset_report.json"
    manifest_path = tmp_path / "dataset_manifest.json"

    df = build_dataset_mod.build_dataset(
        normal_count=0,
        attack_ratio=0.5,
        campaign_id="campaign_test",
        target_app="crapi",
        lab_run_id="lab_run_123",
        is_replay=True,
        output=str(dataset_path),
        report_path=str(report_path),
        manifest_path=str(manifest_path),
    )

    assert isinstance(df, pd.DataFrame)
    assert dataset_path.exists()
    assert report_path.exists()
    assert manifest_path.exists()

    out_df = pd.read_parquet(dataset_path)
    expected_columns = {
        "scenario_type",
        "target_app",
        "attack_family",
        "attack_technique",
        "validation_tier",
        "lab_run_id",
        "effect_outcome",
        "is_replay",
    }
    assert expected_columns.issubset(set(out_df.columns))
    assert set(out_df["target_app"].unique()) == {"crapi"}
    assert set(out_df["lab_run_id"].unique()) == {"lab_run_123"}
    assert set(out_df["is_replay"].unique()) == {True}

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "2.0"
    assert manifest["campaign_id"] == "campaign_test"
    assert manifest["target_app"] == "crapi"
    assert manifest["lab_run_id"] == "lab_run_123"
    assert "scenario_types" in manifest["distributions"]
    assert "validation_tiers" in manifest["distributions"]


def test_build_dataset_requires_full_static_sources() -> None:
    try:
        build_dataset_mod.build_dataset(require_static_full=True, normal_count=0, attack_ratio=0.5)
    except ValueError as exc:
        assert "required sources are missing" in str(exc).lower()
    else:
        raise AssertionError("Expected ValueError when --require-static-full is enabled.")
