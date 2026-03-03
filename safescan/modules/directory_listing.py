"""Open directory listing detection module.

Checks common paths (e.g., /images/, /uploads/, /assets/) for signs of an
auto-generated directory index returned by the web server.
"""

from __future__ import annotations
from typing import Any
import re

import requests

# Common directories to probe.
COMMON_DIRS: list[str] = [
    "/",
    "/images/",
    "/uploads/",
    "/assets/",
    "/static/",
    "/backup/",
    "/files/",
]

# Heuristic patterns that indicate a directory listing.
DIR_LISTING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<title>Index of /", re.I),
    re.compile(r"Directory listing for", re.I),
    re.compile(r"\[To Parent Directory\]", re.I),
    re.compile(r"<h1>Index of", re.I),
]


def check_directory_listing(url: str, **kwargs: Any) -> list[dict]:
    """Return findings if any common path exposes a directory listing."""
    findings: list[dict] = []

    base = url.rstrip("/")

    for path in COMMON_DIRS:
        target = f"{base}{path}"
        try:
            resp = requests.get(target, timeout=10, allow_redirects=True)
        except requests.RequestException:
            continue

        for pattern in DIR_LISTING_PATTERNS:
            if pattern.search(resp.text):
                findings.append(
                    {
                        "check": "directory_listing",
                        "severity": "medium",
                        "detail": f"Directory listing detected at {target}",
                        "recommendation": (
                            "Disable automatic directory indexes in your web server "
                            "configuration (e.g., 'Options -Indexes' in Apache, "
                            "'autoindex off;' in Nginx)."
                        ),
                    }
                )
                break  # one match per path is enough

    if not findings:
        findings.append(
            {
                "check": "directory_listing",
                "severity": "info",
                "detail": "No open directory listings detected on common paths.",
                "recommendation": "No action needed.",
            }
        )

    return findings
