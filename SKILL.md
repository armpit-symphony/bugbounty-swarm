---
name: bugbounty-swarm
description: Bug bounty swarm with OpenClaw integration, evidence capture, and reporting.
version: 1.0.0
---

# Bug Bounty Swarm Skill

## Install

```bash
bash scripts/install_self.sh
```

## Run (OpenClaw)

```bash
python3 swarm_orchestrator.py example.com \
  --profile cautious \
  --run-vuln \
  --authorized \
  --openclaw \
  --schema-repair \
  --summary-json output/openclaw_summary.json \
  --artifact-dir output/artifacts
```

## Key Outputs

- `output/openclaw_summary.json`
- `output/openclaw_schema_report.json`
- `output/artifacts/` (reports + evidence bundle)
- `output/dashboard.html`

## Safety

- Scope enforced via `configs/scope.json`
- Focus mode via `configs/focus.yaml`
- Strict schema validation by default
