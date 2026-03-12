PYTHON ?= python3
UV ?= uv

.PHONY: help venv install install-dev bootstrap setup-data layer1 layer3 all weekly smoke test

help:
	@echo "Targets:"
	@echo "  venv         Create .venv with uv"
	@echo "  install      Install runtime dependencies"
	@echo "  install-dev  Install runtime + dev dependencies"
	@echo "  bootstrap    Create workspace folders"
	@echo "  setup-data   Clone/update public payload repositories"
	@echo "  layer1       Run Layer-1 (dataset -> train -> validate -> benchmark)"
	@echo "  layer3       Run Layer-3 (telemetry -> anomaly training)"
	@echo "  all          Run Layer-1 + Layer-3"
	@echo "  weekly       Run weekly retrain orchestration"
	@echo "  smoke        Validate CLI entrypoints (--help)"
	@echo "  test         Run pytest"

venv:
	UV_CACHE_DIR=/tmp/.uv-cache $(UV) venv --clear .venv

install:
	UV_CACHE_DIR=/tmp/.uv-cache UV_PROJECT_ENVIRONMENT=.venv $(UV) pip install -r requirements.txt

install-dev:
	UV_CACHE_DIR=/tmp/.uv-cache UV_PROJECT_ENVIRONMENT=.venv $(UV) pip install -r requirements.txt
	UV_CACHE_DIR=/tmp/.uv-cache UV_PROJECT_ENVIRONMENT=.venv $(UV) pip install pytest pytest-cov

bootstrap:
	./scripts/bootstrap_workspace.sh

setup-data:
	./scripts/setup_data_sources.sh

layer1:
	./scripts/run_layer1_pipeline.sh

layer3:
	./scripts/run_layer3_pipeline.sh

all:
	./scripts/run_all_pipelines.sh

weekly:
	./scripts/weekly_retrain.sh

smoke:
	.venv/bin/python -m training.build_dataset --help
	.venv/bin/python -m training.build_lab_dataset --help
	.venv/bin/python -m training.train_attack_model --help
	.venv/bin/python -m training.validate_model --help
	.venv/bin/python -m training.train_anomaly_model --help
	.venv/bin/python -m training.benchmark_inference --help
	.venv/bin/python -m training.bundle_packager --help
	.venv/bin/python scripts/fetch_telemetry.py --help

test:
	.venv/bin/python -m pytest -q
