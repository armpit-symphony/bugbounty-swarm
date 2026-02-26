"""Triage agent to de-duplicate and score findings."""

from __future__ import annotations

import hashlib


def _fingerprint(finding: dict) -> str:
    key_parts = [
        str(finding.get("type", "")),
        str(finding.get("url", "")),
        str(finding.get("parameter", "")),
        str(finding.get("payload", "")),
        str(finding.get("issue", "")),
    ]
    raw = "|".join(key_parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def triage_findings(findings: list[dict]) -> list[dict]:
    seen = set()
    triaged = []
    for f in findings:
        fp = _fingerprint(f)
        if fp in seen:
            continue
        seen.add(fp)
        f = dict(f)
        f["confidence"] = _score(f)
        triaged.append(f)
    return triaged


def _score(finding: dict) -> float:
    severity = (finding.get("severity") or "MEDIUM").upper()
    base = {
        "CRITICAL": 0.9,
        "HIGH": 0.75,
        "MEDIUM": 0.5,
        "LOW": 0.3,
    }.get(severity, 0.4)
    indicators = finding.get("indicators") or finding.get("details") or []
    if indicators:
        base += 0.1
    return min(base, 0.99)
