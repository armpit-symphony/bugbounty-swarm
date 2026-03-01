#!/usr/bin/env python3
"""Heartbeat writer for SparkPit Labs surfaces.

Appends one JSONL line to control/heartbeats/<surface>.jsonl every time it runs.
Designed to be called from cron or surface_snapshot.sh.

Usage:
    python3 tools/heartbeat_write.py
    python3 tools/heartbeat_write.py --surface do-droplet
    python3 tools/heartbeat_write.py --surface aws-ec2 --repos /var/www/app /home/deploy/handoff

Environment:
    SURFACE_NAME  — override surface identifier (default: hostname)
    SWARM_ROOT    — repo root (default: parent of this file)
"""

from __future__ import annotations

import datetime
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_REPOS = [
    str(REPO_ROOT),
    str(REPO_ROOT.parent / "sparkpitlabs_handoff"),
    "/home/sparky/wepo",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _git_info(path: str) -> dict:
    p = Path(path)
    if not (p / ".git").exists():
        return {"path": path, "status": "not-a-git-repo"}
    def _run(cmd):
        try:
            return subprocess.check_output(cmd, cwd=path, stderr=subprocess.DEVNULL).decode().strip()
        except Exception:
            return "unknown"
    branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    commit = _run(["git", "rev-parse", "--short", "HEAD"])
    dirty_count = len([
        l for l in _run(["git", "status", "--porcelain"]).splitlines() if l.strip()
    ])
    return {"path": path, "branch": branch, "commit": commit, "dirty_files": dirty_count}


def _uptime_s() -> int | str:
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except Exception:
        return "unknown"


def _services() -> list[str]:
    results = []
    # Docker
    if shutil.which("docker"):
        try:
            out = subprocess.check_output(
                ["docker", "ps", "--format", "{{.Names}} {{.Status}}"],
                stderr=subprocess.DEVNULL,
            ).decode()
            results.extend(out.strip().splitlines()[:10])
        except Exception:
            pass
    # systemd
    if shutil.which("systemctl"):
        try:
            out = subprocess.check_output(
                ["systemctl", "list-units", "--type=service", "--state=running",
                 "--no-pager", "--no-legend"],
                stderr=subprocess.DEVNULL,
            ).decode()
            for line in out.strip().splitlines()[:10]:
                parts = line.split()
                if parts:
                    results.append(parts[0])
        except Exception:
            pass
    return results


def _cron_summary() -> str:
    try:
        out = subprocess.check_output(["crontab", "-l"], stderr=subprocess.DEVNULL).decode()
        active = [l for l in out.splitlines() if l.strip() and not l.startswith("#")]
        return f"{len(active)} user crontab entries"
    except Exception:
        return "no user crontab"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def write_heartbeat(
    surface: str | None = None,
    repos: list[str] | None = None,
    output_dir: str | None = None,
) -> Path:
    surface = surface or os.environ.get("SURFACE_NAME") or socket.gethostname()
    repos = repos or DEFAULT_REPOS
    output_root = Path(output_dir or (REPO_ROOT / "control" / "heartbeats"))
    output_root.mkdir(parents=True, exist_ok=True)

    record = {
        "ts": datetime.datetime.utcnow().isoformat() + "Z",
        "surface": surface,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "uptime_s": _uptime_s(),
        "repos": [_git_info(r) for r in repos if Path(r).exists()],
        "services": _services(),
        "cron_summary": _cron_summary(),
    }

    out_file = output_root / f"{surface}.jsonl"
    with open(out_file, "a") as f:
        f.write(json.dumps(record) + "\n")

    print(f"[heartbeat] wrote to {out_file}")
    print(json.dumps(record, indent=2))
    return out_file


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Write a heartbeat JSONL record for this surface")
    parser.add_argument("--surface", default="", help="Surface identifier (default: hostname)")
    parser.add_argument("--repos", nargs="*", default=[], help="Key repo paths to record git state for")
    parser.add_argument("--output-dir", default="", help="Directory for heartbeat files (default: control/heartbeats/)")
    args = parser.parse_args()

    write_heartbeat(
        surface=args.surface or None,
        repos=args.repos or None,
        output_dir=args.output_dir or None,
    )
