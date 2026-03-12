#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${DATA_DIR:-${ROOT_DIR}/data}"
PAYLOADS_DIR="${PAYLOADS_DIR:-${DATA_DIR}/PayloadAllTheThings}"
SECLISTS_DIR="${SECLISTS_DIR:-${DATA_DIR}/SecLists}"
SKIP_DOCKER="${SKIP_DOCKER:-0}"

mkdir -p "${DATA_DIR}/dast" "${DATA_DIR}/raw" "${DATA_DIR}/intermediate" "${DATA_DIR}/curated"

echo "Preparing local data sources under ${DATA_DIR}"

if [ -d "${PAYLOADS_DIR}/.git" ]; then
  echo "Updating PayloadAllTheThings..."
  git -C "${PAYLOADS_DIR}" pull --ff-only
else
  echo "Cloning PayloadAllTheThings..."
  git clone https://github.com/swisskyrepo/PayloadAllTheThings.git "${PAYLOADS_DIR}"
fi

if [ -d "${SECLISTS_DIR}/.git" ]; then
  echo "Updating SecLists..."
  git -C "${SECLISTS_DIR}" pull --ff-only
else
  echo "Cloning SecLists (sparse checkout)..."
  git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/danielmiessler/SecLists.git "${SECLISTS_DIR}"
  git -C "${SECLISTS_DIR}" sparse-checkout set Fuzzing Discovery/Web-Content
fi

if [ "${SKIP_DOCKER}" != "1" ] && command -v docker >/dev/null 2>&1; then
  echo "Pulling OWASP Juice Shop image..."
  docker pull bkimminich/juice-shop:latest
fi

echo "Data source setup complete."
echo "Optional DAST exports:"
echo "  ${DATA_DIR}/dast/burp_export.xml"
echo "  ${DATA_DIR}/dast/zap_report.json"
echo "  ${DATA_DIR}/dast/acunetix_export.json"
