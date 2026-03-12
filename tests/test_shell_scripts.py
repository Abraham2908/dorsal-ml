from __future__ import annotations

import subprocess
from pathlib import Path


def test_shell_scripts_have_valid_syntax() -> None:
    scripts = [
        "scripts/bootstrap_workspace.sh",
        "scripts/setup_data_sources.sh",
        "scripts/run_layer1_pipeline.sh",
        "scripts/run_layer3_pipeline.sh",
        "scripts/run_all_pipelines.sh",
        "scripts/weekly_retrain.sh",
    ]
    for script in scripts:
        path = Path(script)
        proc = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
        assert proc.returncode == 0, f"{script}: {proc.stderr}"
