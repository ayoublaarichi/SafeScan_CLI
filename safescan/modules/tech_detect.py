"""Technology detection module.

Fingerprints the target by inspecting common HTTP response headers
(Server, X-Powered-By, X-AspNet-Version, X-Generator, etc.).
"""

from __future__ import annotations
from typing import Any

import requests

# Headers that leak technology / version information.
TECH_HEADERS: dict[str, str] = {
    "Server": "Server header reveals web-server software and version.",
    "X-Powered-By": "X-Powered-By header reveals backend technology.",
    "X-AspNet-Version": "X-AspNet-Version header reveals ASP.NET version.",
    "X-Generator": "X-Generator header reveals the CMS or site generator.",
}


def check_tech(url: str, **kwargs: Any) -> list[dict]:
    """Detect technologies exposed through HTTP response headers."""
    findings: list[dict] = []

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException as exc:
        findings.append(
            {
                "check": "tech_detect",
                "severity": "low",
                "detail": f"Could not fetch URL for tech detection: {exc}",
                "recommendation": "Ensure the target URL is reachable.",
            }
        )
        return findings

    headers_lower = {k.lower(): (k, v) for k, v in resp.headers.items()}

    for header, description in TECH_HEADERS.items():
        key = header.lower()
        if key in headers_lower:
            original_name, value = headers_lower[key]
            findings.append(
                {
                    "check": "tech_detect",
                    "severity": "low",
                    "detail": f"{description} Value: {value}",
                    "recommendation": (
                        f"Consider removing or obfuscating the {original_name} header "
                        "to reduce information leakage."
                    ),
                }
            )

    if not findings:
        findings.append(
            {
                "check": "tech_detect",
                "severity": "info",
                "detail": "No technology-revealing headers found.",
                "recommendation": "No action needed.",
            }
        )

    return findings
