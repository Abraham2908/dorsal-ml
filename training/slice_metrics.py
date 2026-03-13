"""Slice-level evaluation utilities for Layer-1 model governance."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


DEFAULT_SLICE_COLUMNS = (
    "source_family",
    "category",
    "campaign_id",
    "scenario_type",
    "target_app",
    "validation_tier",
    "attack_family",
)


def _confusion_parts(y_true: np.ndarray, y_pred: np.ndarray) -> tuple[int, int, int, int]:
    y_true_arr = np.asarray(y_true, dtype=np.int32)
    y_pred_arr = np.asarray(y_pred, dtype=np.int32)
    tp = int(((y_true_arr == 1) & (y_pred_arr == 1)).sum())
    fp = int(((y_true_arr == 0) & (y_pred_arr == 1)).sum())
    tn = int(((y_true_arr == 0) & (y_pred_arr == 0)).sum())
    fn = int(((y_true_arr == 1) & (y_pred_arr == 0)).sum())
    return tp, fp, tn, fn


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, Any]:
    tp, fp, tn, fn = _confusion_parts(y_true, y_pred)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    return {
        "precision": float(precision),
        "recall": float(recall),
        "fpr": float(fpr),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def build_slice_report(
    *,
    df: pd.DataFrame,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    row_indices: np.ndarray,
    slice_columns: tuple[str, ...] = DEFAULT_SLICE_COLUMNS,
    min_support: int = 3,
) -> dict[str, dict[str, dict[str, Any]]]:
    report: dict[str, dict[str, dict[str, Any]]] = {}
    subset = df.iloc[row_indices].copy()
    subset["y_true"] = np.asarray(y_true, dtype=np.int32)
    subset["y_pred"] = np.asarray(y_pred, dtype=np.int32)

    for column in slice_columns:
        if column not in subset.columns:
            continue
        grouped: dict[str, dict[str, Any]] = {}
        for value, part in subset.groupby(column, dropna=False):
            n = len(part)
            if n < min_support:
                continue
            metrics = binary_metrics(
                part["y_true"].to_numpy(dtype=np.int32),
                part["y_pred"].to_numpy(dtype=np.int32),
            )
            grouped[str(value)] = {"n": int(n), **metrics}
        report[column] = grouped
    return report


def load_slice_gate_rules(config_path: str | None) -> list[dict[str, Any]]:
    if not config_path:
        return []
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Slice gates config not found: {path}")
    with open(path, "r", encoding="utf-8") as file:
        raw = json.load(file)

    if isinstance(raw, list):
        rules = raw
    elif isinstance(raw, dict):
        rules = raw.get("rules", [])
    else:
        raise ValueError("Slice gates config must be a JSON object or list.")

    normalized: list[dict[str, Any]] = []
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"Invalid gate rule at index {idx}: expected object.")
        column = rule.get("column")
        if not column:
            raise ValueError(f"Invalid gate rule at index {idx}: missing 'column'.")
        normalized_rule = {
            "column": str(column),
            "value": str(rule["value"]) if "value" in rule else None,
            "min_support": int(rule.get("min_support", 20)),
            "min_precision": rule.get("min_precision"),
            "min_recall": rule.get("min_recall"),
            "max_fpr": rule.get("max_fpr"),
        }
        normalized.append(normalized_rule)
    return normalized


def _compare_thresholds(
    *,
    metrics: dict[str, Any],
    rule: dict[str, Any],
    failures: list[dict[str, Any]],
    column: str,
    value: str,
) -> None:
    min_precision = rule.get("min_precision")
    min_recall = rule.get("min_recall")
    max_fpr = rule.get("max_fpr")

    if min_precision is not None and metrics["precision"] < float(min_precision):
        failures.append(
            {
                "column": column,
                "value": value,
                "metric": "precision",
                "value_observed": float(metrics["precision"]),
                "threshold": float(min_precision),
            }
        )
    if min_recall is not None and metrics["recall"] < float(min_recall):
        failures.append(
            {
                "column": column,
                "value": value,
                "metric": "recall",
                "value_observed": float(metrics["recall"]),
                "threshold": float(min_recall),
            }
        )
    if max_fpr is not None and metrics["fpr"] > float(max_fpr):
        failures.append(
            {
                "column": column,
                "value": value,
                "metric": "fpr",
                "value_observed": float(metrics["fpr"]),
                "threshold": float(max_fpr),
            }
        )


def evaluate_slice_gates(
    *,
    slice_report: dict[str, dict[str, dict[str, Any]]],
    gate_rules: list[dict[str, Any]],
    default_min_support: int = 20,
) -> dict[str, Any]:
    if not gate_rules:
        return {
            "enabled": False,
            "passed": True,
            "rules_evaluated": 0,
            "failures": [],
        }

    failures: list[dict[str, Any]] = []
    for rule in gate_rules:
        column = str(rule["column"])
        expected_value = rule.get("value")
        min_support = int(rule.get("min_support", default_min_support))
        column_report = slice_report.get(column, {})
        if not column_report:
            failures.append({"column": column, "reason": "missing_column"})
            continue

        if expected_value is not None:
            value_key = str(expected_value)
            metrics = column_report.get(value_key)
            if metrics is None:
                failures.append({"column": column, "value": value_key, "reason": "missing_slice"})
                continue
            if int(metrics.get("n", 0)) < min_support:
                failures.append(
                    {
                        "column": column,
                        "value": value_key,
                        "reason": "insufficient_support",
                        "n": int(metrics.get("n", 0)),
                        "min_support": min_support,
                    }
                )
                continue
            _compare_thresholds(
                metrics=metrics,
                rule=rule,
                failures=failures,
                column=column,
                value=value_key,
            )
            continue

        eligible = [
            (key, metrics)
            for key, metrics in column_report.items()
            if int(metrics.get("n", 0)) >= min_support
        ]
        if not eligible:
            failures.append(
                {
                    "column": column,
                    "reason": "no_slice_with_min_support",
                    "min_support": min_support,
                }
            )
            continue
        for value_key, metrics in eligible:
            _compare_thresholds(
                metrics=metrics,
                rule=rule,
                failures=failures,
                column=column,
                value=str(value_key),
            )

    return {
        "enabled": True,
        "passed": not failures,
        "rules_evaluated": len(gate_rules),
        "failures": failures,
    }
