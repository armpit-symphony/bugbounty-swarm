"""OpenClaw schema validation helper."""

from __future__ import annotations

import json
from pathlib import Path


def load_schema(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def validate(summary: dict, schema: dict) -> list[str]:
    errors = []
    for field, ftype in schema.get("fields", {}).items():
        if field not in summary:
            errors.append(f"missing:{field}")
            continue
        if ftype == "string" and not isinstance(summary[field], str):
            errors.append(f"type:{field}")
        if ftype == "array" and not isinstance(summary[field], list):
            errors.append(f"type:{field}")
        if ftype == "object" and not isinstance(summary[field], dict):
            errors.append(f"type:{field}")
    return errors
