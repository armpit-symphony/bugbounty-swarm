#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "Installing skill..."
bash "$REPO_DIR/scripts/install_self.sh"

echo "Running swarm (cautious, OpenClaw)..."
python3 "$REPO_DIR/swarm_orchestrator.py" "${1:-example.com}" \
  --profile cautious \
  --run-vuln \
  --authorized \
  --openclaw \
  --schema-repair \
  --summary-json "$REPO_DIR/output/openclaw_summary.json" \
  --artifact-dir "$REPO_DIR/output/artifacts"
