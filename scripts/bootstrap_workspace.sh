#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "${ROOT_DIR}/data/raw"
mkdir -p "${ROOT_DIR}/data/intermediate"
mkdir -p "${ROOT_DIR}/data/curated"
mkdir -p "${ROOT_DIR}/data/dast"
mkdir -p "${ROOT_DIR}/data/telemetry"
mkdir -p "${ROOT_DIR}/models"
mkdir -p "${ROOT_DIR}/models/bundles"
mkdir -p "${ROOT_DIR}/reports"
mkdir -p "${ROOT_DIR}/keys"
mkdir -p "${ROOT_DIR}/logs"

echo "Workspace bootstrap complete:"
echo "  ${ROOT_DIR}/data/{raw,intermediate,curated,dast,telemetry}"
echo "  ${ROOT_DIR}/models/bundles"
echo "  ${ROOT_DIR}/reports"
echo "  ${ROOT_DIR}/keys"
echo "  ${ROOT_DIR}/logs"
