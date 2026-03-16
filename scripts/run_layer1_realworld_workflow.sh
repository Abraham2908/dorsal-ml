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
UNSW_NB15_DIR="${UNSW_NB15_DIR:-${DATA_DIR}/academic/UNSW-NB15}"
CIC_IDS_DIR="${CIC_IDS_DIR:-${DATA_DIR}/academic/CIC-IDS}"
JUICESHOP_TRAFFIC_DIR="${JUICESHOP_TRAFFIC_DIR:-${DATA_DIR}/raw/static/juiceshop}"
DVWA_TRAFFIC_DIR="${DVWA_TRAFFIC_DIR:-${DATA_DIR}/raw/static/dvwa}"
MODSEC_CRS_DIR="${MODSEC_CRS_DIR:-${DATA_DIR}/coreruleset}"
NVD_SNAPSHOT_FILE="${NVD_SNAPSHOT_FILE:-${DATA_DIR}/nvd/nvd_api_snapshot.json}"
COMMONCRAWL_DIR="${COMMONCRAWL_DIR:-${DATA_DIR}/commoncrawl}"
STATIC_PROFILE="${STATIC_PROFILE:-classic}"
TARGET_APP="${TARGET_APP:-unknown}"
LAB_RUN_ID="${LAB_RUN_ID:-}"
IS_REPLAY="${IS_REPLAY:-0}"
HARD_NEGATIVES_PATH="${HARD_NEGATIVES_PATH:-}"
HARD_NEGATIVE_RATIO="${HARD_NEGATIVE_RATIO:-0.0}"
SCENARIO_PROFILE="${SCENARIO_PROFILE:-default}"

TRAIN_ATTACK_RATIO="${TRAIN_ATTACK_RATIO:-0.20}"
TRAIN_NORMAL_COUNT="${TRAIN_NORMAL_COUNT:-0}"
TRAIN_MAX_PER_CATEGORY="${TRAIN_MAX_PER_CATEGORY:-5000}"
TRAIN_CAMPAIGN_ID="${TRAIN_CAMPAIGN_ID:-campaign_train_${DATE_TAG}}"

REALWORLD_ATTACK_RATIO="${REALWORLD_ATTACK_RATIO:-0.02}"
REALWORLD_NORMAL_COUNT="${REALWORLD_NORMAL_COUNT:-0}"
REALWORLD_MAX_PER_CATEGORY="${REALWORLD_MAX_PER_CATEGORY:-5000}"
REALWORLD_CAMPAIGN_ID="${REALWORLD_CAMPAIGN_ID:-campaign_realworld_${DATE_TAG}}"

N_ESTIMATORS="${N_ESTIMATORS:-300}"
MAX_DEPTH="${MAX_DEPTH:-20}"
TEST_SIZE="${TEST_SIZE:-0.2}"

MIN_PRECISION="${MIN_PRECISION:-0.92}"
MIN_RECALL="${MIN_RECALL:-0.85}"
MAX_FPR="${MAX_FPR:-0.03}"
MAX_LATENCY_P99_MS="${MAX_LATENCY_P99_MS:-2.0}"
BENCHMARK_ITERATIONS="${BENCHMARK_ITERATIONS:-10000}"
SLICE_MIN_SUPPORT="${SLICE_MIN_SUPPORT:-20}"
SLICE_GATES_CONFIG="${SLICE_GATES_CONFIG:-}"

REALWORLD_MIN_PRECISION="${REALWORLD_MIN_PRECISION:-0.85}"
REALWORLD_MIN_RECALL="${REALWORLD_MIN_RECALL:-0.80}"
REALWORLD_MAX_FPR="${REALWORLD_MAX_FPR:-0.01}"
REALWORLD_MAX_LATENCY_P99_MS="${REALWORLD_MAX_LATENCY_P99_MS:-2.0}"
REALWORLD_ITERATIONS="${REALWORLD_ITERATIONS:-10000}"

MODEL_NAME="${MODEL_NAME:-attack_rw_${DATE_TAG}}"
MODEL_OUT="${MODEL_OUT:-${MODELS_DIR}/${MODEL_NAME}.onnx}"
TRAIN_DATASET_OUT="${TRAIN_DATASET_OUT:-${DATA_DIR}/curated/${MODEL_NAME}.train.parquet}"
TRAIN_DATASET_REPORT="${TRAIN_DATASET_REPORT:-${REPORTS_DIR}/${MODEL_NAME}.train.dataset_report.json}"
TRAIN_BENCHMARK_OUT="${TRAIN_BENCHMARK_OUT:-${REPORTS_DIR}/${MODEL_NAME}.train.benchmark.json}"
REALWORLD_DATASET_OUT="${REALWORLD_DATASET_OUT:-${DATA_DIR}/curated/${MODEL_NAME}.realworld.parquet}"
REALWORLD_DATASET_REPORT="${REALWORLD_DATASET_REPORT:-${REPORTS_DIR}/${MODEL_NAME}.realworld.dataset_report.json}"
REALWORLD_SUMMARY_OUT="${REALWORLD_SUMMARY_OUT:-${REPORTS_DIR}/${MODEL_NAME}.realworld_summary.json}"
TRAIN_DATASET_MANIFEST="${TRAIN_DATASET_MANIFEST:-${REPORTS_DIR}/${MODEL_NAME}.train.dataset_manifest.json}"
REALWORLD_DATASET_MANIFEST="${REALWORLD_DATASET_MANIFEST:-${REPORTS_DIR}/${MODEL_NAME}.realworld.dataset_manifest.json}"
TRAIN_VALIDATION_REPORT="${TRAIN_VALIDATION_REPORT:-${REPORTS_DIR}/${MODEL_NAME}.train.validation.json}"
REALWORLD_VALIDATION_REPORT="${REALWORLD_VALIDATION_REPORT:-${REPORTS_DIR}/${MODEL_NAME}.realworld.validation.json}"
PROMOTION_REPORT="${PROMOTION_REPORT:-${REPORTS_DIR}/${MODEL_NAME}.promotion_decision.json}"
TRAIN_LAB_RUN_ID="${TRAIN_LAB_RUN_ID:-${LAB_RUN_ID}}"
REALWORLD_LAB_RUN_ID="${REALWORLD_LAB_RUN_ID:-${LAB_RUN_ID}}"
TRAIN_IS_REPLAY="${TRAIN_IS_REPLAY:-${IS_REPLAY}}"
REALWORLD_IS_REPLAY="${REALWORLD_IS_REPLAY:-${IS_REPLAY}}"

mkdir -p "${DATA_DIR}/curated" "${MODELS_DIR}" "${REPORTS_DIR}" "${MODELS_DIR}/bundles"

if [ ! -x "${PYTHON_BIN}" ]; then
  echo "Python not found at ${PYTHON_BIN}"
  echo "Create the environment first: uv venv .venv && UV_PROJECT_ENVIRONMENT=.venv uv pip install -r requirements.txt"
  exit 1
fi

BUILD_SOURCE_ARGS=()
ATTACK_SOURCE_COUNT=0

if [ "${STATIC_PROFILE}" = "full" ]; then
  BUILD_SOURCE_ARGS+=(--require-static-full)
  BUILD_SOURCE_ARGS+=(--payloads-dir "${PAYLOADS_DIR}")
  BUILD_SOURCE_ARGS+=(--seclists-dir "${SECLISTS_DIR}")
  BUILD_SOURCE_ARGS+=(--unsw-nb15-dir "${UNSW_NB15_DIR}")
  BUILD_SOURCE_ARGS+=(--cic-ids-dir "${CIC_IDS_DIR}")
  BUILD_SOURCE_ARGS+=(--juiceshop-traffic-dir "${JUICESHOP_TRAFFIC_DIR}")
  BUILD_SOURCE_ARGS+=(--dvwa-traffic-dir "${DVWA_TRAFFIC_DIR}")
  BUILD_SOURCE_ARGS+=(--modsec-crs-dir "${MODSEC_CRS_DIR}")
  BUILD_SOURCE_ARGS+=(--nvd-snapshot-file "${NVD_SNAPSHOT_FILE}")
  BUILD_SOURCE_ARGS+=(--commoncrawl-dir "${COMMONCRAWL_DIR}")
else
  if [ -d "${PAYLOADS_DIR}" ]; then
    BUILD_SOURCE_ARGS+=(--payloads-dir "${PAYLOADS_DIR}")
    ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
  fi
  if [ -d "${SECLISTS_DIR}" ]; then
    BUILD_SOURCE_ARGS+=(--seclists-dir "${SECLISTS_DIR}")
    ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
  fi
  if [ -d "${UNSW_NB15_DIR}" ]; then
    BUILD_SOURCE_ARGS+=(--unsw-nb15-dir "${UNSW_NB15_DIR}")
    ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
  fi
  if [ -d "${CIC_IDS_DIR}" ]; then
    BUILD_SOURCE_ARGS+=(--cic-ids-dir "${CIC_IDS_DIR}")
    ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
  fi
  if [ -d "${JUICESHOP_TRAFFIC_DIR}" ]; then
    BUILD_SOURCE_ARGS+=(--juiceshop-traffic-dir "${JUICESHOP_TRAFFIC_DIR}")
    ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
  fi
  if [ -d "${DVWA_TRAFFIC_DIR}" ]; then
    BUILD_SOURCE_ARGS+=(--dvwa-traffic-dir "${DVWA_TRAFFIC_DIR}")
    ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
  fi
  if [ -d "${MODSEC_CRS_DIR}" ]; then
    BUILD_SOURCE_ARGS+=(--modsec-crs-dir "${MODSEC_CRS_DIR}")
    ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
  fi
  if [ -f "${NVD_SNAPSHOT_FILE}" ]; then
    BUILD_SOURCE_ARGS+=(--nvd-snapshot-file "${NVD_SNAPSHOT_FILE}")
    ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
  fi
  if [ -d "${COMMONCRAWL_DIR}" ]; then
    BUILD_SOURCE_ARGS+=(--commoncrawl-dir "${COMMONCRAWL_DIR}")
  fi
fi
if [ -n "${BURP_FILE}" ] && [ -f "${BURP_FILE}" ]; then
  BUILD_SOURCE_ARGS+=(--burp-file "${BURP_FILE}")
  ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
fi
if [ -n "${ZAP_FILE}" ] && [ -f "${ZAP_FILE}" ]; then
  BUILD_SOURCE_ARGS+=(--zap-file "${ZAP_FILE}")
  ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
fi
if [ -n "${ACUNETIX_FILE}" ] && [ -f "${ACUNETIX_FILE}" ]; then
  BUILD_SOURCE_ARGS+=(--acunetix-file "${ACUNETIX_FILE}")
  ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
fi
if [ -n "${STRIX_RUNS_DIR}" ] && [ -d "${STRIX_RUNS_DIR}" ]; then
  BUILD_SOURCE_ARGS+=(--strix-runs-dir "${STRIX_RUNS_DIR}")
  ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
fi
if [ -n "${SHANNON_SESSIONS_DIR}" ] && [ -d "${SHANNON_SESSIONS_DIR}" ]; then
  BUILD_SOURCE_ARGS+=(--shannon-sessions-dir "${SHANNON_SESSIONS_DIR}")
  ATTACK_SOURCE_COUNT=$((ATTACK_SOURCE_COUNT + 1))
fi

if [ "${ATTACK_SOURCE_COUNT}" -eq 0 ] && [ "${STATIC_PROFILE}" != "full" ]; then
  echo "No attack sources found."
  echo "Run: make setup-data"
  echo "Or set attack-capable sources (payload repos, DAST exports, agent snapshots, static datasets)."
  exit 1
fi

echo "[L1-REAL] Step 1/6 - Build training dataset (attack_ratio=${TRAIN_ATTACK_RATIO})..."
TRAIN_BUILD_ARGS=(
  -m training.build_dataset
  --normal-count "${TRAIN_NORMAL_COUNT}"
  --attack-ratio "${TRAIN_ATTACK_RATIO}"
  --hard-negative-ratio "${HARD_NEGATIVE_RATIO}"
  --scenario-profile "${SCENARIO_PROFILE}"
  --max-per-category "${TRAIN_MAX_PER_CATEGORY}"
  --campaign-id "${TRAIN_CAMPAIGN_ID}"
  --target-app "${TARGET_APP}"
  --report-path "${TRAIN_DATASET_REPORT}"
  --manifest-path "${TRAIN_DATASET_MANIFEST}"
  --output "${TRAIN_DATASET_OUT}"
)
if [ -n "${TRAIN_LAB_RUN_ID}" ]; then
  TRAIN_BUILD_ARGS+=(--lab-run-id "${TRAIN_LAB_RUN_ID}")
fi
if [ -n "${HARD_NEGATIVES_PATH}" ] && [ -e "${HARD_NEGATIVES_PATH}" ]; then
  TRAIN_BUILD_ARGS+=(--hard-negatives-path "${HARD_NEGATIVES_PATH}")
fi
case "${TRAIN_IS_REPLAY,,}" in
  1|true|yes|on)
    TRAIN_BUILD_ARGS+=(--is-replay)
    ;;
esac
"${PYTHON_BIN}" "${TRAIN_BUILD_ARGS[@]}" "${BUILD_SOURCE_ARGS[@]}"

echo "[L1-REAL] Step 2/6 - Train model on training dataset..."
TRAIN_MODEL_ARGS=(
  -m training.train_attack_model
  --dataset "${TRAIN_DATASET_OUT}"
  --output "${MODEL_OUT}"
  --n-estimators "${N_ESTIMATORS}"
  --max-depth "${MAX_DEPTH}"
  --test-size "${TEST_SIZE}"
  --min-precision "${MIN_PRECISION}"
  --min-recall "${MIN_RECALL}"
  --max-fpr "${MAX_FPR}"
  --slice-min-support "${SLICE_MIN_SUPPORT}"
)
if [ -n "${SLICE_GATES_CONFIG}" ]; then
  TRAIN_MODEL_ARGS+=(--slice-gates-config "${SLICE_GATES_CONFIG}")
fi
"${PYTHON_BIN}" "${TRAIN_MODEL_ARGS[@]}"

echo "[L1-REAL] Step 3/6 - Validate model on training dataset..."
set +e
TRAIN_VALIDATE_ARGS=(
  -m training.validate_model
  --model "${MODEL_OUT}"
  --dataset "${TRAIN_DATASET_OUT}"
  --min-precision "${MIN_PRECISION}"
  --min-recall "${MIN_RECALL}"
  --max-fpr "${MAX_FPR}"
  --max-latency-p99 "${MAX_LATENCY_P99_MS}"
  --iterations "${BENCHMARK_ITERATIONS}"
  --slice-min-support "${SLICE_MIN_SUPPORT}"
  --report-json "${TRAIN_VALIDATION_REPORT}"
)
if [ -n "${SLICE_GATES_CONFIG}" ]; then
  TRAIN_VALIDATE_ARGS+=(--slice-gates-config "${SLICE_GATES_CONFIG}")
fi
"${PYTHON_BIN}" "${TRAIN_VALIDATE_ARGS[@]}"
TRAIN_VALIDATE_EXIT=$?
set -e

echo "[L1-REAL] Step 4/6 - Build real-world evaluation dataset (attack_ratio=${REALWORLD_ATTACK_RATIO})..."
REALWORLD_BUILD_ARGS=(
  -m training.build_dataset
  --normal-count "${REALWORLD_NORMAL_COUNT}"
  --attack-ratio "${REALWORLD_ATTACK_RATIO}"
  --hard-negative-ratio "${HARD_NEGATIVE_RATIO}"
  --scenario-profile "${SCENARIO_PROFILE}"
  --max-per-category "${REALWORLD_MAX_PER_CATEGORY}"
  --campaign-id "${REALWORLD_CAMPAIGN_ID}"
  --target-app "${TARGET_APP}"
  --report-path "${REALWORLD_DATASET_REPORT}"
  --manifest-path "${REALWORLD_DATASET_MANIFEST}"
  --output "${REALWORLD_DATASET_OUT}"
)
if [ -n "${REALWORLD_LAB_RUN_ID}" ]; then
  REALWORLD_BUILD_ARGS+=(--lab-run-id "${REALWORLD_LAB_RUN_ID}")
fi
if [ -n "${HARD_NEGATIVES_PATH}" ] && [ -e "${HARD_NEGATIVES_PATH}" ]; then
  REALWORLD_BUILD_ARGS+=(--hard-negatives-path "${HARD_NEGATIVES_PATH}")
fi
case "${REALWORLD_IS_REPLAY,,}" in
  1|true|yes|on)
    REALWORLD_BUILD_ARGS+=(--is-replay)
    ;;
esac
"${PYTHON_BIN}" "${REALWORLD_BUILD_ARGS[@]}" "${BUILD_SOURCE_ARGS[@]}"

echo "[L1-REAL] Step 5/6 - Validate model on real-world evaluation dataset..."
set +e
REALWORLD_VALIDATE_ARGS=(
  -m training.validate_model
  --model "${MODEL_OUT}"
  --dataset "${REALWORLD_DATASET_OUT}"
  --min-precision "${REALWORLD_MIN_PRECISION}"
  --min-recall "${REALWORLD_MIN_RECALL}"
  --max-fpr "${REALWORLD_MAX_FPR}"
  --max-latency-p99 "${REALWORLD_MAX_LATENCY_P99_MS}"
  --iterations "${REALWORLD_ITERATIONS}"
  --slice-min-support "${SLICE_MIN_SUPPORT}"
  --report-json "${REALWORLD_VALIDATION_REPORT}"
)
if [ -n "${SLICE_GATES_CONFIG}" ]; then
  REALWORLD_VALIDATE_ARGS+=(--slice-gates-config "${SLICE_GATES_CONFIG}")
fi
"${PYTHON_BIN}" "${REALWORLD_VALIDATE_ARGS[@]}"
REALWORLD_VALIDATE_EXIT=$?
set -e

echo "[L1-REAL] Step 6/6 - Benchmark and write summary..."
"${PYTHON_BIN}" -m training.benchmark_inference \
  --model "${MODEL_OUT}" \
  --dataset "${TRAIN_DATASET_OUT}" \
  --iterations "${BENCHMARK_ITERATIONS}" \
  --output-json "${TRAIN_BENCHMARK_OUT}"

set +e
"${PYTHON_BIN}" -m training.promotion_gate \
  --train-eval "${MODEL_OUT%.onnx}.eval.json" \
  --validation-eval "${TRAIN_VALIDATION_REPORT}" \
  --validation-eval "${REALWORLD_VALIDATION_REPORT}" \
  --output "${PROMOTION_REPORT}"
PROMOTION_EXIT=$?
set -e

"${PYTHON_BIN}" - "${MODEL_OUT}" "${REALWORLD_DATASET_OUT}" "${TRAIN_DATASET_REPORT}" "${REALWORLD_DATASET_REPORT}" "${MODEL_OUT%.onnx}.eval.json" "${REALWORLD_SUMMARY_OUT}" "${TRAIN_VALIDATE_EXIT}" "${REALWORLD_VALIDATE_EXIT}" "${PROMOTION_EXIT}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import onnxruntime as ort
import pandas as pd


def _extract_preds(raw_output):
    if isinstance(raw_output, np.ndarray):
        if raw_output.ndim == 1:
            if np.issubdtype(raw_output.dtype, np.floating):
                return (raw_output >= 0.5).astype(np.int32)
            return raw_output.astype(np.int32)
        if raw_output.ndim == 2:
            if raw_output.shape[1] == 1:
                return (raw_output[:, 0] >= 0.5).astype(np.int32)
            return np.argmax(raw_output, axis=1).astype(np.int32)
    if isinstance(raw_output, list):
        if raw_output and isinstance(raw_output[0], dict):
            probs = []
            for row in raw_output:
                if 1 in row:
                    probs.append(float(row[1]))
                elif "1" in row:
                    probs.append(float(row["1"]))
                else:
                    probs.append(max(float(v) for v in row.values()))
            return (np.asarray(probs, dtype=np.float32) >= 0.5).astype(np.int32)
        return np.asarray(raw_output, dtype=np.int32)
    return np.asarray(raw_output, dtype=np.int32)


def _metrics(y_true, y_pred):
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    return {
        "precision": float(precision),
        "recall": float(recall),
        "fpr": float(fpr),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def _read_json(path):
    p = Path(path)
    if not p.exists():
        return {}
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


model_path = Path(sys.argv[1])
eval_dataset_path = Path(sys.argv[2])
train_dataset_report_path = Path(sys.argv[3])
realworld_dataset_report_path = Path(sys.argv[4])
train_eval_json_path = Path(sys.argv[5])
summary_out_path = Path(sys.argv[6])
train_validate_exit = int(sys.argv[7])
realworld_validate_exit = int(sys.argv[8])
promotion_exit = int(sys.argv[9])

model_meta = _read_json(str(model_path.with_suffix(".json")))
feature_names = model_meta.get("feature_names", [])
eval_df = pd.read_parquet(eval_dataset_path)
X = np.nan_to_num(eval_df[feature_names].to_numpy(dtype=np.float32), nan=0.0, posinf=1e6, neginf=-1e6)
y = eval_df["label"].to_numpy(dtype=np.int32)

session = ort.InferenceSession(str(model_path))
input_name = session.get_inputs()[0].name
raw_pred = session.run(None, {input_name: X})[0]
y_pred = _extract_preds(raw_pred)
realworld_metrics = _metrics(y, y_pred)

summary = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "model_path": str(model_path),
    "training_dataset": _read_json(str(train_dataset_report_path)),
    "realworld_dataset": _read_json(str(realworld_dataset_report_path)),
    "training_metrics": _read_json(str(train_eval_json_path)).get("overall", {}),
    "realworld_metrics": realworld_metrics,
    "validation_exit_codes": {
        "training_validation": train_validate_exit,
        "realworld_validation": realworld_validate_exit,
        "promotion_gate": promotion_exit,
    },
    "passed": bool(train_validate_exit == 0 and realworld_validate_exit == 0 and promotion_exit == 0),
}

summary_out_path.parent.mkdir(parents=True, exist_ok=True)
with open(summary_out_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)
PY

PASSED=0
if [ "${TRAIN_VALIDATE_EXIT}" -eq 0 ] && [ "${REALWORLD_VALIDATE_EXIT}" -eq 0 ] && [ "${PROMOTION_EXIT}" -eq 0 ]; then
  PASSED=1
fi

if [ "${PASSED}" -eq 1 ]; then
  LATEST_MODEL="${MODELS_DIR}/attack_latest.onnx"
  cp "${MODEL_OUT}" "${LATEST_MODEL}"
  cp "${MODEL_OUT%.onnx}.json" "${MODELS_DIR}/attack_latest.json"
  cp "${MODEL_OUT%.onnx}.eval.json" "${MODELS_DIR}/attack_latest.eval.json"
  cp "${TRAIN_VALIDATION_REPORT}" "${MODELS_DIR}/attack_latest.validation_train.json"
  cp "${REALWORLD_VALIDATION_REPORT}" "${MODELS_DIR}/attack_latest.validation_realworld.json"
  cp "${PROMOTION_REPORT}" "${MODELS_DIR}/attack_latest.promotion.json"
  cp "${MODEL_OUT%.onnx}.features.json" "${MODELS_DIR}/attack_latest.features.json"
  cp "${MODEL_OUT%.onnx}.manifest.json" "${MODELS_DIR}/attack_latest.manifest.json"

  if [ -n "${DORSAL_MODEL_SIGNING_PRIVATE_KEY:-}" ] && [ -n "${DORSAL_MODEL_KEK:-}" ]; then
    BUNDLE_DIR="${MODELS_DIR}/bundles/${MODEL_NAME}"
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
  echo "Layer-1 real-world workflow complete and approved."
  echo "Model:     ${MODEL_OUT}"
  echo "Summary:   ${REALWORLD_SUMMARY_OUT}"
  echo "Promotion: ${PROMOTION_REPORT}"
else
  echo ""
  echo "Layer-1 real-world workflow finished but failed quality gates."
  echo "Summary: ${REALWORLD_SUMMARY_OUT}"
  exit 1
fi
