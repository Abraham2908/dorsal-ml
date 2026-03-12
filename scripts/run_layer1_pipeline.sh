#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
DATE_TAG="$(date +%Y%m%d_%H%M%S)"

DATA_DIR="${DATA_DIR:-${ROOT_DIR}/data}"
MODELS_DIR="${MODELS_DIR:-${ROOT_DIR}/models}"
REPORTS_DIR="${REPORTS_DIR:-${ROOT_DIR}/reports}"

PAYLOADS_DIR="${PAYLOADS_DIR:-${DATA_DIR}/PayloadAllTheThings}"
SECLISTS_DIR="${SECLISTS_DIR:-${DATA_DIR}/SecLists}"
BURP_FILE="${BURP_FILE:-}"
ZAP_FILE="${ZAP_FILE:-}"
ACUNETIX_FILE="${ACUNETIX_FILE:-}"
STRIX_RUNS_DIR="${STRIX_RUNS_DIR:-}"
SHANNON_SESSIONS_DIR="${SHANNON_SESSIONS_DIR:-}"

NORMAL_COUNT="${NORMAL_COUNT:-100000}"
ATTACK_RATIO="${ATTACK_RATIO:-0.2}"
MAX_PER_CATEGORY="${MAX_PER_CATEGORY:-5000}"
CAMPAIGN_ID="${CAMPAIGN_ID:-campaign_${DATE_TAG}}"

N_ESTIMATORS="${N_ESTIMATORS:-300}"
MAX_DEPTH="${MAX_DEPTH:-20}"
TEST_SIZE="${TEST_SIZE:-0.2}"

MIN_PRECISION="${MIN_PRECISION:-0.92}"
MIN_RECALL="${MIN_RECALL:-0.85}"
MAX_FPR="${MAX_FPR:-0.03}"
MAX_LATENCY_P99_MS="${MAX_LATENCY_P99_MS:-2.0}"
BENCHMARK_ITERATIONS="${BENCHMARK_ITERATIONS:-10000}"

MODEL_NAME="${MODEL_NAME:-attack_${DATE_TAG}}"
DATASET_OUT="${DATASET_OUT:-${DATA_DIR}/curated/${MODEL_NAME}.parquet}"
DATASET_REPORT="${DATASET_REPORT:-${REPORTS_DIR}/${MODEL_NAME}.dataset_report.json}"
MODEL_OUT="${MODEL_OUT:-${MODELS_DIR}/${MODEL_NAME}.onnx}"
BENCHMARK_OUT="${BENCHMARK_OUT:-${REPORTS_DIR}/${MODEL_NAME}.benchmark.json}"

mkdir -p "${DATA_DIR}/curated" "${MODELS_DIR}" "${REPORTS_DIR}" "${MODELS_DIR}/bundles"

if [ ! -x "${PYTHON_BIN}" ]; then
  echo "Python not found at ${PYTHON_BIN}"
  echo "Create the environment first: uv venv .venv && UV_PROJECT_ENVIRONMENT=.venv uv pip install -r requirements.txt"
  exit 1
fi

BUILD_ARGS=(
  -m training.build_dataset
  --normal-count "${NORMAL_COUNT}"
  --attack-ratio "${ATTACK_RATIO}"
  --max-per-category "${MAX_PER_CATEGORY}"
  --campaign-id "${CAMPAIGN_ID}"
  --report-path "${DATASET_REPORT}"
  --output "${DATASET_OUT}"
)

ATTACK_SOURCE_COUNT=0

if [ -d "${PAYLOADS_DIR}" ]; then
  BUILD_ARGS+=(--payloads-dir "${PAYLOADS_DIR}")
  ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
fi
if [ -d "${SECLISTS_DIR}" ]; then
  BUILD_ARGS+=(--seclists-dir "${SECLISTS_DIR}")
  ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
fi

if [ -n "${BURP_FILE}" ] && [ -f "${BURP_FILE}" ]; then
  BUILD_ARGS+=(--burp-file "${BURP_FILE}")
  ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
fi
if [ -n "${ZAP_FILE}" ] && [ -f "${ZAP_FILE}" ]; then
  BUILD_ARGS+=(--zap-file "${ZAP_FILE}")
  ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
fi
if [ -n "${ACUNETIX_FILE}" ] && [ -f "${ACUNETIX_FILE}" ]; then
  BUILD_ARGS+=(--acunetix-file "${ACUNETIX_FILE}")
  ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
fi
if [ -n "${STRIX_RUNS_DIR}" ] && [ -d "${STRIX_RUNS_DIR}" ]; then
  BUILD_ARGS+=(--strix-runs-dir "${STRIX_RUNS_DIR}")
  ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
fi
if [ -n "${SHANNON_SESSIONS_DIR}" ] && [ -d "${SHANNON_SESSIONS_DIR}" ]; then
  BUILD_ARGS+=(--shannon-sessions-dir "${SHANNON_SESSIONS_DIR}")
  ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
fi

if [ "${ATTACK_SOURCE_COUNT}" -eq 0 ]; then
  echo "No attack sources found."
  echo "Run: make setup-data"
  echo "Or set BURP_FILE/ZAP_FILE/ACUNETIX_FILE/STRIX_RUNS_DIR/SHANNON_SESSIONS_DIR."
  exit 1
fi

echo "[L1] Building dataset..."
"${PYTHON_BIN}" "${BUILD_ARGS[@]}"

echo "[L1] Training attack model..."
"${PYTHON_BIN}" -m training.train_attack_model \
  --dataset "${DATASET_OUT}" \
  --output "${MODEL_OUT}" \
  --n-estimators "${N_ESTIMATORS}" \
  --max-depth "${MAX_DEPTH}" \
  --test-size "${TEST_SIZE}" \
  --min-precision "${MIN_PRECISION}" \
  --min-recall "${MIN_RECALL}" \
  --max-fpr "${MAX_FPR}"

echo "[L1] Validating attack model..."
"${PYTHON_BIN}" -m training.validate_model \
  --model "${MODEL_OUT}" \
  --dataset "${DATASET_OUT}" \
  --min-precision "${MIN_PRECISION}" \
  --min-recall "${MIN_RECALL}" \
  --max-fpr "${MAX_FPR}" \
  --max-latency-p99 "${MAX_LATENCY_P99_MS}" \
  --iterations "${BENCHMARK_ITERATIONS}"

echo "[L1] Benchmarking ONNX latency/parity..."
"${PYTHON_BIN}" -m training.benchmark_inference \
  --model "${MODEL_OUT}" \
  --dataset "${DATASET_OUT}" \
  --iterations "${BENCHMARK_ITERATIONS}" \
  --output-json "${BENCHMARK_OUT}"

LATEST_MODEL="${MODELS_DIR}/attack_latest.onnx"
cp "${MODEL_OUT}" "${LATEST_MODEL}"
cp "${MODEL_OUT%.onnx}.json" "${MODELS_DIR}/attack_latest.json"
cp "${MODEL_OUT%.onnx}.eval.json" "${MODELS_DIR}/attack_latest.eval.json"
cp "${MODEL_OUT%.onnx}.features.json" "${MODELS_DIR}/attack_latest.features.json"
cp "${MODEL_OUT%.onnx}.manifest.json" "${MODELS_DIR}/attack_latest.manifest.json"

if [ -n "${DORSAL_MODEL_SIGNING_PRIVATE_KEY:-}" ] && [ -n "${DORSAL_MODEL_KEK:-}" ]; then
  BUNDLE_DIR="${MODELS_DIR}/bundles/${MODEL_NAME}"
  echo "[L1] Packaging encrypted bundle..."
  "${PYTHON_BIN}" -m training.bundle_packager package \
    --model "${MODEL_OUT}" \
    --feature-map "${MODEL_OUT%.onnx}.features.json" \
    --output-dir "${BUNDLE_DIR}" \
    --private-key "${DORSAL_MODEL_SIGNING_PRIVATE_KEY}" \
    --kek "${DORSAL_MODEL_KEK}" \
    --model-id "attack_v1" \
    --model-version "${MODEL_NAME}" \
    --min-gateway-version "${MIN_GATEWAY_VERSION:-0.1.0}"
fi

echo ""
echo "Layer-1 pipeline complete."
echo "Dataset:   ${DATASET_OUT}"
echo "Model:     ${MODEL_OUT}"
echo "Benchmark: ${BENCHMARK_OUT}"
