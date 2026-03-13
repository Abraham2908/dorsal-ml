from __future__ import annotations

import json

import pandas as pd

from training.gateway_correlator import (
    build_labeled_dataset_from_lab,
    correlate_logs_with_findings,
)


def test_correlator_adds_new_metadata_columns() -> None:
    gateway_df = pd.DataFrame(
        [
            {
                "timestamp": pd.Timestamp("2026-03-10T12:00:00Z"),
                "method": "GET",
                "path": "/api/users",
                "query_string": "id=1",
                "body": "' OR 1=1 --",
            }
        ]
    )
    findings_df = pd.DataFrame(
        [
            {
                "timestamp": pd.Timestamp("2026-03-10T12:00:01Z"),
                "method": "GET",
                "path": "/api/users",
                "payload": "' OR 1=1 --",
                "category": "sqli",
                "source": "burp",
                "title": "SQLi finding",
            }
        ]
    )

    out = correlate_logs_with_findings(
        gateway_df=gateway_df,
        findings_df=findings_df,
        campaign_id="campaign_lab_1",
        target_app="crapi",
        lab_run_id="lab_run_1",
        is_replay=True,
    )

    assert out.loc[0, "label"] == 1
    assert out.loc[0, "match_tier"] == "confirmed_exact"
    assert out.loc[0, "validation_tier"] == "gold"
    assert out.loc[0, "effect_outcome"] == "attempt_only"
    assert out.loc[0, "scenario_type"] == "scanner_dast"
    assert out.loc[0, "target_app"] == "crapi"
    assert out.loc[0, "lab_run_id"] == "lab_run_1"
    assert bool(out.loc[0, "is_replay"]) is True


def test_build_labeled_dataset_from_lab_writes_manifest(monkeypatch, tmp_path) -> None:
    gateway_log = tmp_path / "gateway.jsonl"
    gateway_log.write_text(
        json.dumps(
            {
                "timestamp": "2026-03-10T12:00:00Z",
                "method": "GET",
                "path": "/api/users",
                "query_string": "id=1",
                "body": "' OR 1=1 --",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "training.gateway_correlator.load_agent_findings",
        lambda **kwargs: pd.DataFrame(
            [
                {
                    "timestamp": pd.Timestamp("2026-03-10T12:00:01Z"),
                    "method": "GET",
                    "path": "/api/users",
                    "payload": "' OR 1=1 --",
                    "category": "sqli",
                    "source": "zap",
                }
            ]
        ),
    )

    output_path = tmp_path / "dataset_lab.parquet"
    manifest_path = tmp_path / "dataset_lab_manifest.json"
    build_labeled_dataset_from_lab(
        gateway_log_path=str(gateway_log),
        output_path=str(output_path),
        campaign_id="campaign_lab_2",
        target_app="vapi",
        lab_run_id="lab_run_2",
        is_replay=False,
        manifest_path=str(manifest_path),
    )

    assert output_path.exists()
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "2.0"
    assert manifest["campaign_id"] == "campaign_lab_2"
    assert manifest["target_app"] == "vapi"
    assert "match_tiers" in manifest["distributions"]
