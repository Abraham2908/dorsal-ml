from __future__ import annotations

import json

import numpy as np
import pandas as pd

import training.build_dataset as build_dataset_mod


class _DummyFeatures:
    def to_array(self) -> np.ndarray:
        size = len(build_dataset_mod.RequestFeatures.feature_names())
        return np.zeros(size, dtype=np.float32)


def test_build_dataset_uses_hard_negatives(monkeypatch, tmp_path) -> None:
    attacks = [
        {
            "payload": "' OR 1=1 --",
            "method": "GET",
            "path": "/api/login",
            "source": "PayloadAllTheThings",
            "source_file": "sqli.txt",
            "category": "sqli",
            "label": 1,
            "label_confidence": 0.97,
        }
    ]

    hard_negatives = tmp_path / "hard_negatives.jsonl"
    hard_negatives.write_text(
        "\n".join(
            [
                json.dumps({"method": "POST", "path": "/api/orders", "payload": "{\"status\":\"pending\"}"}),
                json.dumps({"method": "GET", "path": "/api/search", "payload": "sort=desc&page=2"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    def _fake_normals(*, n: int, api_types=None):
        captured["normal_n"] = n
        captured["api_types"] = api_types
        return []

    monkeypatch.setattr(build_dataset_mod, "_collect_local_attack_records", lambda **kwargs: attacks)
    monkeypatch.setattr(build_dataset_mod, "generate_normal_requests", _fake_normals)
    monkeypatch.setattr(build_dataset_mod, "extract_features_from_payload", lambda **kwargs: _DummyFeatures())

    dataset_path = tmp_path / "dataset.parquet"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "manifest.json"
    df = build_dataset_mod.build_dataset(
        normal_count=0,
        attack_ratio=0.5,
        hard_negatives_path=str(hard_negatives),
        hard_negative_ratio=1.0,
        scenario_profile="b2b",
        campaign_id="campaign_hn",
        output=str(dataset_path),
        report_path=str(report_path),
        manifest_path=str(manifest_path),
    )

    assert isinstance(df, pd.DataFrame)
    out_df = pd.read_parquet(dataset_path)
    assert int((out_df["scenario_type"] == "hard_negative").sum()) == 1
    assert int((out_df["label"] == 0).sum()) == 1
    assert captured["normal_n"] == 0
    assert captured["api_types"] == ["saas_b2b", "fintech"]

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["data_sources"]["hard_negatives_path"] == str(hard_negatives)
    assert manifest["parameters"]["hard_negative_ratio"] == 1.0
