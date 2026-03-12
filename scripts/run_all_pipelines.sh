#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"${ROOT_DIR}/scripts/bootstrap_workspace.sh"
"${ROOT_DIR}/scripts/run_layer1_pipeline.sh"
"${ROOT_DIR}/scripts/run_layer3_pipeline.sh"

echo ""
echo "All training pipelines completed."
