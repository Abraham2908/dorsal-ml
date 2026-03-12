# Repository Guidelines

## Project Structure & Module Organization
Core code is split by responsibility:
- `training/`: dataset assembly, model training, validation, and correlation jobs (`build_dataset.py`, `train_attack_model.py`, `validate_model.py`).
- `parsers/`: ingestion/parsing for payload repos, DAST exports, gateway telemetry, and agent feeds.
- `utils/`: shared feature engineering utilities.
- `agents/`: agent-facing package entry points.
- `configs/`: pipeline configuration (for example `pipeline_config.json`).
- `scripts/`: operational scripts for setup and weekly retraining.
- `docs-examples/`: reference documents; not runtime code.

Keep new modules in the closest existing package and prefer explicit imports (`from training...`, `from parsers...`).

## Build, Test, and Development Commands
- `python3 -m venv .venv && source .venv/bin/activate`: create local virtualenv.
- `pip install -r requirements.txt`: install runtime and test dependencies.
- `./scripts/setup_data_sources.sh`: clone/update payload sources and prepare `data/`.
- `python -m training.build_dataset --help`: inspect dataset build options.
- `python -m training.train_attack_model --dataset ./data/dataset_v1.parquet --output ./models/attack_v1.onnx`: train attack model.
- `python -m training.validate_model --model ./models/attack_v1.onnx --dataset ./data/dataset_v1.parquet`: run quality/latency gates.
- `pytest -q`: run tests (add `--cov` when coverage is needed).

## Coding Style & Naming Conventions
Target Python 3.11+ with PEP 8 conventions:
- 4-space indentation, `snake_case` for functions/files, `PascalCase` for classes, `UPPER_SNAKE_CASE` for constants.
- Prefer type hints on public functions and small, single-purpose modules.
- Keep CLI entrypoints under `training/` and parsing logic under `parsers/`.

No formatter/linter config is committed yet; use `ruff` and `black` locally before opening a PR.

## Testing Guidelines
Use `pytest` with tests under `tests/` mirroring source paths (example: `tests/training/test_validate_model.py`).
- Name files `test_*.py` and test functions `test_*`.
- Add unit tests for feature extraction and parser edge cases (malformed XML/JSON, missing fields).
- For training/validation changes, include at least one integration-style test on a small fixture dataset.

## Commit & Pull Request Guidelines
This repo currently has no commit history; adopt Conventional Commits from now on:
- `feat(training): add threshold flag`
- `fix(parsers): handle empty zap alerts`

PRs should include:
- Clear summary and affected paths.
- Repro/run commands used (`build_dataset`, `train_attack_model`, `pytest`).
- Linked issue/ticket when available.
- Before/after metrics for model-related changes (precision, recall, FPR, latency P99).
