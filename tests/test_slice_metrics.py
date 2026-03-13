from __future__ import annotations

import json

import numpy as np
import pandas as pd

from training.slice_metrics import (
    build_slice_report,
    evaluate_slice_gates,
    load_slice_gate_rules,
)


def test_build_slice_report_and_gate_pass() -> None:
    df = pd.DataFrame(
        {
            "scenario_type": ["scanner_dast", "scanner_dast", "scanner_dast", "legit_background"],
            "target_app": ["crapi", "crapi", "crapi", "crapi"],
        }
    )
    y_true = np.array([1, 1, 0, 0], dtype=np.int32)
    y_pred = np.array([1, 1, 0, 0], dtype=np.int32)
    idx = np.arange(len(df))

    report = build_slice_report(df=df, y_true=y_true, y_pred=y_pred, row_indices=idx, min_support=1)
    gates = [{"column": "scenario_type", "value": "scanner_dast", "min_support": 2, "min_recall": 0.9}]
    decision = evaluate_slice_gates(slice_report=report, gate_rules=gates, default_min_support=2)
    assert decision["passed"] is True
    assert decision["failures"] == []


def test_slice_gate_detects_failure(tmp_path) -> None:
    df = pd.DataFrame(
        {
            "validation_tier": ["gold", "gold", "gold", "gold"],
        }
    )
    y_true = np.array([1, 1, 1, 0], dtype=np.int32)
    y_pred = np.array([1, 0, 0, 0], dtype=np.int32)
    report = build_slice_report(
        df=df,
        y_true=y_true,
        y_pred=y_pred,
        row_indices=np.arange(len(df)),
        min_support=1,
    )

    config = tmp_path / "slice_gates.json"
    config.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "column": "validation_tier",
                        "value": "gold",
                        "min_support": 2,
                        "min_recall": 0.9,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rules = load_slice_gate_rules(str(config))
    decision = evaluate_slice_gates(slice_report=report, gate_rules=rules, default_min_support=2)
    assert decision["passed"] is False
    assert decision["failures"][0]["metric"] == "recall"
