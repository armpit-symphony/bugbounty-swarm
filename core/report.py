"""Report writer: JSON, Markdown, HTML."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def _ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def write_json(path: str, data: dict) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(data, f, indent=2)
    return str(p)


def write_markdown(path: str, md: str) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        f.write(md)
    return str(p)


def write_html(path: str, title: str, body: str) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #111; }}
    h1 {{ margin-bottom: 8px; }}
    h2 {{ margin-top: 24px; }}
    code {{ background: #f6f6f6; padding: 2px 4px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #f2f2f2; }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""
    with open(p, "w") as f:
        f.write(html)
    return str(p)
