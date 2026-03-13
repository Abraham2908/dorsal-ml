"""Promotion gate evaluator for Layer-1 model artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _read_json(path: str) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Artifact not found: {file_path}")
    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid JSON artifact (expected object): {file_path}")
    return data


def _artifact_status(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "passed": bool(payload.get("passed", False)),
        "slice_gates_passed": bool(payload.get("slice_gates", {}).get("passed", True)),
        "overall": payload.get("overall", {}),
        "slice_gates": payload.get("slice_gates", {}),
    }


def evaluate_promotion(
    *,
    train_eval_path: str,
    validation_eval_paths: list[str],
    output_path: str | None = None,
) -> dict[str, Any]:
    train_eval = _read_json(train_eval_path)
    validations = [_read_json(path) for path in validation_eval_paths]

    statuses = [_artifact_status("train_eval", train_eval)]
    for idx, payload in enumerate(validations, start=1):
        statuses.append(_artifact_status(f"validation_{idx}", payload))

    failures: list[dict[str, Any]] = []
    for status in statuses:
        if not status["passed"]:
            failures.append({"artifact": status["name"], "reason": "artifact_failed"})
        if not status["slice_gates_passed"]:
            failures.append({"artifact": status["name"], "reason": "slice_gates_failed"})

    decision = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "train_eval_path": train_eval_path,
        "validation_eval_paths": validation_eval_paths,
        "artifacts": statuses,
        "failed_checks": failures,
        "passed": not failures,
    }

    out = Path(output_path) if output_path else Path("reports/promotion_decision.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as file:
        json.dump(decision, file, indent=2)
    decision["output_path"] = str(out)
    return decision


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Layer-1 promotion gate")
    parser.add_argument("--train-eval", required=True, help="Path to train .eval.json artifact")
    parser.add_argument(
        "--validation-eval",
        action="append",
        default=[],
        help="Path to validation report json artifact (repeatable)",
    )
    parser.add_argument("--output", help="Path to promotion decision json")
    args = parser.parse_args()

    decision = evaluate_promotion(
        train_eval_path=args.train_eval,
        validation_eval_paths=args.validation_eval,
        output_path=args.output,
    )
    print(f"promotion_passed={decision['passed']} output={decision['output_path']}")
    sys.exit(0 if decision["passed"] else 1)


if __name__ == "__main__":
    main()
