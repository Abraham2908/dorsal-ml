"""Async pipeline worker: orchestrates training and reports back to Control Plane."""

from __future__ import annotations

import logging
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dorsal_train import config
from dorsal_train.control_plane_client import update_training_run, upload_model_bundle

logger = logging.getLogger(__name__)

# In-memory store of active run states (run_id → state dict)
_RUNS: dict[int, dict[str, Any]] = {}

# Root of dorsal-ml repo (parent of dorsal_train/)
_REPO_ROOT = Path(__file__).resolve().parents[1]


def get_run_state(run_id: int) -> dict[str, Any] | None:
    return _RUNS.get(run_id)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _update_local(run_id: int, **kwargs: Any) -> None:
    if run_id in _RUNS:
        _RUNS[run_id].update(kwargs)


def _run_step(run_id: int, step: str, cmd: list[str]) -> subprocess.CompletedProcess:
    logger.info("run=%d step=%s cmd=%s", run_id, step, " ".join(cmd))
    _update_local(run_id, current_step=step)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error("run=%d step=%s FAILED:\n%s", run_id, step, result.stderr[-2000:])
        raise RuntimeError(f"Step {step!r} failed (rc={result.returncode}): {result.stderr[-500:]}")
    logger.info("run=%d step=%s done", run_id, step)
    return result


def execute_training_run(
    run_id: int,
    *,
    mode: str = "all",
    source_ids: list[int] | None = None,
    hyperparams: dict[str, Any] | None = None,
    validation_gates: dict[str, Any] | None = None,
) -> None:
    """Execute the full training pipeline for a given run_id.

    This function is meant to be called in a background thread.
    It updates the Control Plane at each milestone.
    """
    hp = hyperparams or {}
    gates = validation_gates or {}

    _RUNS[run_id] = {
        "run_id": run_id,
        "started_at": _now(),
        "current_step": "initializing",
        "mode": mode,
    }

    try:
        _do_training(run_id, mode=mode, hp=hp, gates=gates)
    except Exception as exc:
        logger.exception("training_run_failed run_id=%d", run_id)
        _update_local(run_id, current_step="failed", error=str(exc))
        try:
            update_training_run(run_id, status="failed", error_message=str(exc)[:1000])
        except Exception:
            logger.exception("failed_to_notify_cp_failure run_id=%d", run_id)
    finally:
        _RUNS.pop(run_id, None)


def _do_training(run_id: int, *, mode: str, hp: dict, gates: dict) -> None:
    data_dir = Path(config.DATA_DIR)
    models_dir = Path(config.MODELS_DIR)
    run_dir = models_dir / f"run_{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)

    dataset_path = run_dir / "dataset.parquet"
    model_onnx = run_dir / "attack_model.onnx"
    eval_json = run_dir / "eval.json"
    bundle_dir = run_dir / "bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    python = sys.executable

    # -----------------------------------------------------------------------
    # Step 1: notify CP — running
    # -----------------------------------------------------------------------
    update_training_run(run_id, status="running", logs_summary="pipeline_started")

    # -----------------------------------------------------------------------
    # Step 2: build dataset
    # -----------------------------------------------------------------------
    build_cmd = [
        python, str(_REPO_ROOT / "training" / "build_dataset.py"),
        "--output", str(dataset_path),
        "--normal-count", str(hp.get("normal_count", 50000)),
        "--attack-ratio", str(hp.get("attack_ratio", 0.35)),
    ]

    # Wire up known static sources if they exist on disk
    _append_if_exists(build_cmd, "--payloads-dir", data_dir / "payloads")
    _append_if_exists(build_cmd, "--seclists-dir", data_dir / "seclists")
    _append_if_exists(build_cmd, "--modsec-crs-dir", data_dir / "coreruleset")
    _append_if_exists(build_cmd, "--unsw-nb15-dir", data_dir / "unsw-nb15")
    _append_if_exists(build_cmd, "--cic-ids-dir", data_dir / "cic-ids")
    _append_if_exists(build_cmd, "--juiceshop-traffic-dir", data_dir / "apps" / "juice-shop")
    _append_if_exists(build_cmd, "--dvwa-traffic-dir", data_dir / "apps" / "dvwa")
    _append_if_exists(build_cmd, "--nvd-snapshot-file", data_dir / "nvd" / "nvd.json")
    _append_if_exists(build_cmd, "--commoncrawl-dir", data_dir / "commoncrawl")

    _run_step(run_id, "build_dataset", build_cmd)

    # -----------------------------------------------------------------------
    # Step 3: train model
    # -----------------------------------------------------------------------
    train_cmd = [
        python, str(_REPO_ROOT / "training" / "train_attack_model.py"),
        "--dataset", str(dataset_path),
        "--output", str(model_onnx),
        "--n-estimators", str(hp.get("n_estimators", 200)),
        "--max-depth", str(hp.get("max_depth", 20)),
        "--min-precision", str(gates.get("min_precision", 0.92)),
        "--min-recall", str(gates.get("min_recall", 0.85)),
        "--max-fpr", str(gates.get("max_fpr", 0.03)),
    ]
    train_result = _run_step(run_id, "train_model", train_cmd)

    # -----------------------------------------------------------------------
    # Step 4: validate model
    # -----------------------------------------------------------------------
    validate_cmd = [
        python, str(_REPO_ROOT / "training" / "validate_model.py"),
        "--model", str(model_onnx),
        "--dataset", str(dataset_path),
        "--output", str(eval_json),
    ]
    _run_step(run_id, "validate_model", validate_cmd)

    # -----------------------------------------------------------------------
    # Step 5: package bundle
    # -----------------------------------------------------------------------
    private_key = _repo_key_path()
    version = _make_version()
    model_id = f"attack-{version}"

    # Feature map is written by train_attack_model alongside the .onnx
    feature_map = run_dir / "attack_model.feature_map.json"
    if not feature_map.exists():
        feature_map = _find_feature_map(run_dir)

    bundle_cmd = [
        python, str(_REPO_ROOT / "training" / "bundle_packager.py"),
        "--model", str(model_onnx),
        "--output-dir", str(bundle_dir),
        "--model-id", model_id,
        "--model-version", version,
        "--min-gateway-version", "0.1.0",
    ]
    if feature_map and feature_map.exists():
        bundle_cmd += ["--feature-map", str(feature_map)]
    if private_key:
        bundle_cmd += ["--private-key", private_key, "--kek-material", "dorsal-dev-kek"]

    _run_step(run_id, "package_bundle", bundle_cmd)

    # -----------------------------------------------------------------------
    # Step 6: upload bundle to Control Plane
    # -----------------------------------------------------------------------
    _update_local(run_id, current_step="uploading")

    bundle_file = _find_bundle_file(bundle_dir)
    if bundle_file is None:
        # Fallback: upload the raw onnx file if no bundle was packaged
        bundle_file = model_onnx

    upload_result = upload_model_bundle(
        name="attack-classifier",
        version=version,
        model_type="classifier",
        description=f"Automated training run {run_id} — mode={mode}",
        bundle_path=bundle_file,
    )
    model_uuid = upload_result.get("id")

    # -----------------------------------------------------------------------
    # Step 7: parse metrics from eval JSON and report completion
    # -----------------------------------------------------------------------
    metrics = _parse_eval_metrics(eval_json)

    update_training_run(
        run_id,
        status="completed",
        model_id=model_uuid,
        logs_summary=f"pipeline_complete version={version}",
        **metrics,
    )
    logger.info("training_run_completed run_id=%d model_id=%s", run_id, model_uuid)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _append_if_exists(cmd: list[str], flag: str, path: Path) -> None:
    if path.exists():
        cmd += [flag, str(path)]


def _make_version() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"1.0.{ts}"


def _repo_key_path() -> str | None:
    candidate = _REPO_ROOT / "keys" / "model_signing_key.pem"
    if candidate.exists():
        return str(candidate)
    return None


def _find_feature_map(run_dir: Path) -> Path | None:
    candidates = list(run_dir.glob("*.feature_map.json")) + list(run_dir.glob("feature_map*.json"))
    return candidates[0] if candidates else None


def _find_bundle_file(bundle_dir: Path) -> Path | None:
    # bundle_packager produces a .bundle or .dorsal file
    for pattern in ("*.bundle", "*.dorsal", "*.zip", "*.tar.gz"):
        candidates = list(bundle_dir.glob(pattern))
        if candidates:
            return candidates[0]
    # Fallback: any file in bundle_dir
    files = [f for f in bundle_dir.iterdir() if f.is_file()]
    return files[0] if files else None


def _parse_eval_metrics(eval_json: Path) -> dict[str, Any]:
    if not eval_json.exists():
        return {}
    import json
    try:
        data = json.loads(eval_json.read_text())
        overall = data.get("overall", {})
        return {
            "precision": overall.get("precision"),
            "recall": overall.get("recall"),
            "fpr": overall.get("fpr"),
            "latency_p99_ms": data.get("latency_p99_ms"),
        }
    except Exception:
        logger.exception("failed_to_parse_eval_json path=%s", eval_json)
        return {}
