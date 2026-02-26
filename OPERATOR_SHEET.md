# Bug Bounty Swarm Operator Sheet

## Quick Start

1. Set scope:
```
configs/scope.json
```

2. Run swarm + vuln:
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

3. Build dashboard:
```bash
python3 scripts/build_dashboard.py
```

## Safe Defaults

- Profile: `cautious`
- Evidence: `standard` (`configs/budget.yaml`)
- Focus: disabled unless `configs/focus.yaml` enabled

## OpenClaw Output

- `output/openclaw_summary.json`
- `output/openclaw_schema_report.json`
- `output/artifacts/` (reports + evidence bundle)

## Evidence Bundle

```bash
python3 scripts/package_evidence.py --output-dir output
```

## Dry Run (no network)

```bash
python3 swarm_orchestrator.py example.com --dry-run
python3 vuln_scanner_orchestrator.py https://example.com --dry-run
```

## Focus Rotation

```bash
python3 scripts/rotate_focus.py --targets "example.com,example.org" --days 56 --enable
```

## Cron Example

```
0 3 * * * /usr/bin/python3 /home/sparky/bugbounty-swarm/scripts/run_focus.py >> /home/sparky/bugbounty-swarm/output/cron.log 2>&1
```
