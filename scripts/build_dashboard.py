#!/usr/bin/env python3
"""Build an HTML dashboard across runs."""

from __future__ import annotations

import json
import os
from pathlib import Path


def _load_reports(output_dir: str):
    reports = []
    for path in Path(output_dir).glob("**/*_report_*.json"):
        try:
            data = json.loads(path.read_text())
            reports.append(("swarm", path.name, data))
        except Exception:
            continue
    for path in Path(output_dir).glob("vuln_scan_*.json"):
        try:
            data = json.loads(path.read_text())
            reports.append(("vuln", path.name, data))
        except Exception:
            continue
    return reports


def main() -> int:
    output_dir = os.getenv("SWARM_OUTPUT_DIR") or "output"
    reports = _load_reports(output_dir)
    rows = ""
    for rtype, name, data in reports:
        target = data.get("target", "")
        ts = data.get("timestamp", "")
        total = data.get("total_findings", "")
        rows += f"<tr><td>{rtype}</td><td>{name}</td><td>{target}</td><td>{ts}</td><td>{total}</td></tr>"

    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Bug Bounty Swarm Dashboard</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 32px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f2f2f2; }}
</style>
</head><body>
<h1>Bug Bounty Swarm Dashboard</h1>
<table>
<tr><th>Type</th><th>Report</th><th>Target</th><th>Timestamp</th><th>Total Findings</th></tr>
{rows}
</table>
</body></html>
"""
    out_path = Path(output_dir) / "dashboard.html"
    out_path.write_text(html)
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
