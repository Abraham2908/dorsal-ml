from __future__ import annotations

import importlib.util
import subprocess
import sys

import pytest


if importlib.util.find_spec("numpy") is None:
    pytestmark = pytest.mark.skip(reason="runtime dependencies are not installed")


@pytest.mark.parametrize(
    "cmd",
    [
        [sys.executable, "-m", "training.build_dataset", "--help"],
        [sys.executable, "-m", "training.build_lab_dataset", "--help"],
        [sys.executable, "-m", "training.train_attack_model", "--help"],
        [sys.executable, "-m", "training.validate_model", "--help"],
        [sys.executable, "-m", "training.train_anomaly_model", "--help"],
        [sys.executable, "-m", "training.benchmark_inference", "--help"],
        [sys.executable, "-m", "training.bundle_packager", "--help"],
        [sys.executable, "scripts/fetch_telemetry.py", "--help"],
    ],
)
def test_cli_help_smoke(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
