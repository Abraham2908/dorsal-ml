#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
LOG_DIR="${LOG_DIR:-${ROOT_DIR}/logs}"
DATE_TAG="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${LOG_DIR}/weekly_retrain_${DATE_TAG}.log"

mkdir -p "${LOG_DIR}"
exec > >(tee -a "${LOG_FILE}") 2>&1

echo "Starting weekly retrain: ${DATE_TAG}"
echo "Repository: ${ROOT_DIR}"

if [ ! -x "${PYTHON_BIN}" ]; then
  echo "Python not found at ${PYTHON_BIN}"
  echo "Install dependencies first."
  exit 1
fi

"${ROOT_DIR}/scripts/bootstrap_workspace.sh"
"${ROOT_DIR}/scripts/setup_data_sources.sh"

if [ "${ENABLE_LAYER1:-1}" = "1" ]; then
  echo "[weekly] Running Layer-1 pipeline..."
  "${ROOT_DIR}/scripts/run_layer1_pipeline.sh"
fi

if [ "${ENABLE_LAYER3:-1}" = "1" ]; then
  echo "[weekly] Running Layer-3 pipeline..."
  "${ROOT_DIR}/scripts/run_layer3_pipeline.sh"
fi

if [ "${ENABLE_GATEWAY_BUILD:-0}" = "1" ] && command -v docker >/dev/null 2>&1; then
  GATEWAY_DIR="${GATEWAY_DIR:-${ROOT_DIR}/../gateway}"
  DOCKER_REGISTRY="${DOCKER_REGISTRY:-ghcr.io/sharkzone/dorsal}"
  if [ -d "${GATEWAY_DIR}" ]; then
    cp "${ROOT_DIR}/models/attack_latest.onnx" "${GATEWAY_DIR}/dorsal/ml/models/attack_v1.onnx"
    docker build -t "${DOCKER_REGISTRY}:${DATE_TAG}" "${GATEWAY_DIR}"
    docker push "${DOCKER_REGISTRY}:${DATE_TAG}"
    docker tag "${DOCKER_REGISTRY}:${DATE_TAG}" "${DOCKER_REGISTRY}:latest"
    docker push "${DOCKER_REGISTRY}:latest"
  else
    echo "Gateway directory not found: ${GATEWAY_DIR}"
  fi
fi

echo "Weekly retrain complete: ${DATE_TAG}"
