"""Scan orchestrator — runs every registered check and collects findings."""

from __future__ import annotations
from typing import Any

from safescan.modules import ALL_CHECKS


def run_scan(url: str, *, param: str | None = None) -> list[dict[str, Any]]:
    """Execute all registered checks against *url* and return a flat list of findings."""
    findings: list[dict[str, Any]] = []

    for check_fn in ALL_CHECKS:
        try:
            results = check_fn(url, param=param)
            findings.extend(results)
        except Exception as exc:  # noqa: BLE001
            findings.append(
                {
                    "check": check_fn.__name__,
                    "severity": "low",
                    "detail": f"Check raised an unexpected error: {exc}",
                    "recommendation": "Review the error and retry.",
                }
            )

    return findings
