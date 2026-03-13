from __future__ import annotations

import json

from training.promotion_gate import evaluate_promotion


def _write_json(path, payload) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_promotion_gate_passes(tmp_path) -> None:
    train = tmp_path / "train.eval.json"
    val = tmp_path / "validation.json"
    out = tmp_path / "promotion.json"

    _write_json(train, {"passed": True, "slice_gates": {"passed": True}, "overall": {"precision": 0.95}})
    _write_json(val, {"passed": True, "slice_gates": {"passed": True}, "overall": {"fpr": 0.01}})

    decision = evaluate_promotion(
        train_eval_path=str(train),
        validation_eval_paths=[str(val)],
        output_path=str(out),
    )
    assert decision["passed"] is True
    assert decision["failed_checks"] == []
    assert out.exists()


def test_promotion_gate_fails_when_slice_gate_fails(tmp_path) -> None:
    train = tmp_path / "train.eval.json"
    val = tmp_path / "validation.json"

    _write_json(train, {"passed": True, "slice_gates": {"passed": True}})
    _write_json(val, {"passed": True, "slice_gates": {"passed": False}})

    decision = evaluate_promotion(
        train_eval_path=str(train),
        validation_eval_paths=[str(val)],
        output_path=str(tmp_path / "promotion.json"),
    )
    assert decision["passed"] is False
    assert decision["failed_checks"][0]["reason"] == "slice_gates_failed"
