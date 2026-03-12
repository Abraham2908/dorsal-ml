#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
DATE_TAG="$(date +%Y%m%d_%H%M%S)"

DATA_DIR="${DATA_DIR:-${ROOT_DIR}/data}"
MODELS_DIR="${MODELS_DIR:-${ROOT_DIR}/models}"

CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-clickhouse.dorsal.internal}"
TELEMETRY_DAYS="${TELEMETRY_DAYS:-14}"
TELEMETRY_INPUT="${TELEMETRY_INPUT:-}"
TELEMETRY_OUT="${TELEMETRY_OUT:-${DATA_DIR}/raw/telemetry_${DATE_TAG}.parquet}"

ANOMALY_MODEL_OUT="${ANOMALY_MODEL_OUT:-${MODELS_DIR}/global_anomaly_${DATE_TAG}.onnx}"
ANOMALY_CONTAMINATION="${ANOMALY_CONTAMINATION:-0.01}"
ANOMALY_ESTIMATORS="${ANOMALY_ESTIMATORS:-200}"
ANOMALY_MAX_FPR="${ANOMALY_MAX_FPR:-0.03}"

mkdir -p "${DATA_DIR}/raw" "${MODELS_DIR}"

if [ ! -x "${PYTHON_BIN}" ]; then
  echo "Python not found at ${PYTHON_BIN}"
  echo "Create the environment first: uv venv .venv && UV_PROJECT_ENVIRONMENT=.venv uv pip install -r requirements.txt"
  exit 1
fi

FETCH_ARGS=(
  scripts/fetch_telemetry.py
  --host "${CLICKHOUSE_HOST}"
  --days "${TELEMETRY_DAYS}"
  --output "${TELEMETRY_OUT}"
)
if [ -n "${TELEMETRY_INPUT}" ]; then
  FETCH_ARGS+=(--input "${TELEMETRY_INPUT}")
fi

echo "[L3] Fetching telemetry snapshot..."
"${PYTHON_BIN}" "${FETCH_ARGS[@]}"

echo "[L3] Training global anomaly model..."
"${PYTHON_BIN}" -m training.train_anomaly_model \
  --input "${TELEMETRY_OUT}" \
  --output "${ANOMALY_MODEL_OUT}" \
  --contamination "${ANOMALY_CONTAMINATION}" \
  --n-estimators "${ANOMALY_ESTIMATORS}" \
  --max-fpr "${ANOMALY_MAX_FPR}"

if [ -f "${ANOMALY_MODEL_OUT}" ]; then
  cp "${ANOMALY_MODEL_OUT}" "${MODELS_DIR}/global_anomaly_latest.onnx"
  ARTIFACT_PATH="${ANOMALY_MODEL_OUT}"
else
  PKL_PATH="${ANOMALY_MODEL_OUT%.onnx}.pkl"
  if [ ! -f "${PKL_PATH}" ]; then
    echo "Global anomaly training produced no artifact (.onnx/.pkl)."
    exit 1
  fi
  cp "${PKL_PATH}" "${MODELS_DIR}/global_anomaly_latest.pkl"
  ARTIFACT_PATH="${PKL_PATH}"
fi

cp "${ANOMALY_MODEL_OUT%.onnx}.json" "${MODELS_DIR}/global_anomaly_latest.json"
cp "${ANOMALY_MODEL_OUT%.onnx}.preproc.json" "${MODELS_DIR}/global_anomaly_latest.preproc.json"

echo ""
echo "Layer-3 pipeline complete."
echo "Telemetry: ${TELEMETRY_OUT}"
echo "Artifact:  ${ARTIFACT_PATH}"
