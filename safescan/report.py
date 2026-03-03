"""Report generation — JSON, HTML, and console output."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

# ── Colour codes for console output ──────────────────────────────────────────
_COLOURS: dict[str, str] = {
    "high": "\033[91m",    # red
    "medium": "\033[93m",  # yellow
    "low": "\033[94m",     # blue
    "info": "\033[90m",    # grey
    "reset": "\033[0m",
}


def _severity_colour(severity: str) -> str:
    return _COLOURS.get(severity, _COLOURS["info"])


# ── Console report ───────────────────────────────────────────────────────────

def print_console_report(findings: list[dict[str, Any]], url: str) -> None:
    """Pretty-print findings to stdout with colours."""
    reset = _COLOURS["reset"]
    print(f"\n{'=' * 60}")
    print(f"  SafeScan Report — {url}")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'=' * 60}\n")

    for f in findings:
        sev = f.get("severity", "info")
        col = _severity_colour(sev)
        print(f"  {col}[{sev.upper():6s}]{reset}  {f['detail']}")

    # Summary counts
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    print(f"\n{'─' * 60}")
    print("  Summary: ", end="")
    print(
        "  ".join(
            f"{_severity_colour(s)}{s.upper()}: {c}{reset}"
            for s, c in sorted(counts.items())
        )
    )
    print(f"{'─' * 60}\n")


# ── JSON report ──────────────────────────────────────────────────────────────

def save_json_report(
    findings: list[dict[str, Any]],
    url: str,
    output_dir: str = "reports",
) -> str:
    """Write findings to a JSON file and return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "report.json")

    report = {
        "scan_target": url,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    return path


# ── HTML report ──────────────────────────────────────────────────────────────

def save_html_report(
    findings: list[dict[str, Any]],
    url: str,
    output_dir: str = "reports",
) -> str:
    """Render findings into a styled HTML report and return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "report.html")

    # Locate the templates/ directory relative to this file's package root.
    pkg_root = Path(__file__).resolve().parent.parent
    template_dir = pkg_root / "templates"

    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("report.html")

    # Summary counts
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    html = template.render(
        url=url,
        scan_time=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        findings=findings,
        counts=counts,
    )

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return path
