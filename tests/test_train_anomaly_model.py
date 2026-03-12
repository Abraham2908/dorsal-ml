from __future__ import annotations

import json

import pandas as pd

from training.train_anomaly_model import train_global_anomaly_model


def test_train_global_anomaly_model_produces_artifact(tmp_path) -> None:
    telemetry = pd.DataFrame(
        {
            "tenant_hash": ["t1", "t1", "t2", "t2", "t3", "t3"],
            "total_requests": [100, 120, 90, 200, 110, 95],
            "body_size_mean": [300.0, 320.0, 250.0, 900.0, 280.0, 260.0],
            "body_size_std": [20.0, 22.0, 15.0, 80.0, 18.0, 17.0],
            "req_per_min_mean": [2.0, 2.2, 1.8, 8.0, 2.1, 1.9],
            "response_size_mean": [512.0, 530.0, 480.0, 1700.0, 500.0, 495.0],
            "error_rate_4xx": [0.02, 0.03, 0.02, 0.25, 0.01, 0.02],
            "error_rate_5xx": [0.0, 0.01, 0.0, 0.08, 0.0, 0.0],
        }
    )
    telemetry_path = tmp_path / "telemetry.parquet"
    telemetry.to_parquet(telemetry_path, index=False)

    output_path = tmp_path / "global_anomaly_v1.onnx"
    result = train_global_anomaly_model(
        telemetry_path=str(telemetry_path),
        output_path=str(output_path),
        contamination=0.2,
        n_estimators=10,
        max_fpr=0.5,
    )

    artifact_path = tmp_path / (
        "global_anomaly_v1.onnx" if result["artifact_format"] == "onnx" else "global_anomaly_v1.pkl"
    )
    assert artifact_path.exists()
    assert result["artifact_path"] == str(artifact_path)

    metadata = json.loads((tmp_path / "global_anomaly_v1.json").read_text(encoding="utf-8"))
    assert metadata["artifact_format"] in {"onnx", "pickle"}
    assert metadata["artifact_path"] == str(artifact_path)
