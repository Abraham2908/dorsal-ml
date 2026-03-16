#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${DATA_DIR:-${ROOT_DIR}/data}"
PAYLOADS_DIR="${PAYLOADS_DIR:-${DATA_DIR}/PayloadAllTheThings}"
SECLISTS_DIR="${SECLISTS_DIR:-${DATA_DIR}/SecLists}"
JUICESHOP_REPO_DIR="${JUICESHOP_REPO_DIR:-${DATA_DIR}/apps/juice-shop}"
DVWA_REPO_DIR="${DVWA_REPO_DIR:-${DATA_DIR}/apps/DVWA}"
MODSEC_CRS_DIR="${MODSEC_CRS_DIR:-${DATA_DIR}/coreruleset}"
UNSW_NB15_DIR="${UNSW_NB15_DIR:-${DATA_DIR}/academic/UNSW-NB15}"
CIC_IDS_DIR="${CIC_IDS_DIR:-${DATA_DIR}/academic/CIC-IDS}"
JUICESHOP_TRAFFIC_DIR="${JUICESHOP_TRAFFIC_DIR:-${DATA_DIR}/raw/static/juiceshop}"
DVWA_TRAFFIC_DIR="${DVWA_TRAFFIC_DIR:-${DATA_DIR}/raw/static/dvwa}"
NVD_SNAPSHOT_FILE="${NVD_SNAPSHOT_FILE:-${DATA_DIR}/nvd/nvd_api_snapshot.json}"
COMMONCRAWL_DIR="${COMMONCRAWL_DIR:-${DATA_DIR}/commoncrawl}"
STATIC_PROFILE="${STATIC_PROFILE:-classic}"
SKIP_DOCKER="${SKIP_DOCKER:-0}"
NVD_API_KEY="${NVD_API_KEY:-}"

mkdir -p \
  "${DATA_DIR}/dast" \
  "${DATA_DIR}/raw" \
  "${DATA_DIR}/intermediate" \
  "${DATA_DIR}/curated" \
  "${DATA_DIR}/apps" \
  "${DATA_DIR}/academic" \
  "${UNSW_NB15_DIR}" \
  "${CIC_IDS_DIR}" \
  "${DATA_DIR}/nvd" \
  "${COMMONCRAWL_DIR}" \
  "${JUICESHOP_TRAFFIC_DIR}" \
  "${DVWA_TRAFFIC_DIR}"

echo "Preparing local data sources under ${DATA_DIR} (profile=${STATIC_PROFILE})"

clone_or_update() {
  local repo_url="$1"
  local target_dir="$2"
  local clone_args="${3:-}"
  if [ -d "${target_dir}/.git" ]; then
    echo "Updating $(basename "${target_dir}")..."
    git -C "${target_dir}" pull --ff-only
    return
  fi
  echo "Cloning $(basename "${target_dir}")..."
  if [ -n "${clone_args}" ]; then
    # shellcheck disable=SC2086
    git clone ${clone_args} "${repo_url}" "${target_dir}"
  else
    git clone "${repo_url}" "${target_dir}"
  fi
}

clone_or_update "https://github.com/swisskyrepo/PayloadsAllTheThings.git" "${PAYLOADS_DIR}"

if [ -d "${SECLISTS_DIR}/.git" ]; then
  echo "Updating SecLists..."
  git -C "${SECLISTS_DIR}" pull --ff-only
else
  echo "Cloning SecLists (sparse checkout)..."
  git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/danielmiessler/SecLists.git "${SECLISTS_DIR}"
  git -C "${SECLISTS_DIR}" sparse-checkout set Fuzzing Discovery/Web-Content
fi

if [ "${STATIC_PROFILE}" = "full" ]; then
  clone_or_update "https://github.com/coreruleset/coreruleset.git" "${MODSEC_CRS_DIR}"
  clone_or_update "https://github.com/juice-shop/juice-shop.git" "${JUICESHOP_REPO_DIR}" "--depth 1"
  clone_or_update "https://github.com/digininja/DVWA.git" "${DVWA_REPO_DIR}" "--depth 1"

  if [ ! -f "${NVD_SNAPSHOT_FILE}" ]; then
    if [ -n "${NVD_API_KEY}" ]; then
      echo "Fetching NVD CVE snapshot..."
      curl -fsSL \
        -H "apiKey: ${NVD_API_KEY}" \
        "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000" \
        -o "${NVD_SNAPSHOT_FILE}"
    else
      echo "Creating placeholder NVD snapshot (set NVD_API_KEY to fetch live data)..."
      printf '{\n  "vulnerabilities": []\n}\n' > "${NVD_SNAPSHOT_FILE}"
    fi
  fi

  echo "Static full profile initialized. Add local snapshots:"
  echo "  UNSW-NB15 CSVs: ${UNSW_NB15_DIR}"
  echo "  CIC-IDS CSVs:   ${CIC_IDS_DIR}"
  echo "  Juice traffic:  ${JUICESHOP_TRAFFIC_DIR}"
  echo "  DVWA traffic:   ${DVWA_TRAFFIC_DIR}"
  echo "  Common Crawl:   ${COMMONCRAWL_DIR}"
  echo "  NVD snapshot:   ${NVD_SNAPSHOT_FILE}"
fi

if [ "${SKIP_DOCKER}" != "1" ] && command -v docker >/dev/null 2>&1; then
  echo "Pulling OWASP Juice Shop image..."
  docker pull bkimminich/juice-shop:latest
fi

echo "Data source setup complete."
if [ "${STATIC_PROFILE}" = "full" ]; then
  echo "Run training with mandatory static sources:"
  echo "  STATIC_PROFILE=full make layer1"
fi
echo "Optional DAST exports:"
echo "  ${DATA_DIR}/dast/burp_export.xml"
echo "  ${DATA_DIR}/dast/zap_report.json"
echo "  ${DATA_DIR}/dast/acunetix_export.json"
