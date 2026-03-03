"""Security-headers check module.

Inspects the HTTP response for missing or weak security headers.
"""

from __future__ import annotations
from typing import Any

import requests

# Header → (severity if missing, recommendation)
EXPECTED_HEADERS: dict[str, tuple[str, str]] = {
    "Content-Security-Policy": (
        "medium",
        "Add a Content-Security-Policy header to mitigate XSS and data-injection attacks. "
        "Start with a restrictive policy such as: default-src 'self';",
    ),
    "Strict-Transport-Security": (
        "medium",
        "Enable HSTS by returning Strict-Transport-Security: max-age=63072000; includeSubDomains; preload "
        "to force browsers to use HTTPS.",
    ),
    "X-Frame-Options": (
        "medium",
        "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.",
    ),
    "X-Content-Type-Options": (
        "low",
        "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
    ),
    "Referrer-Policy": (
        "low",
        "Set a Referrer-Policy header (e.g., strict-origin-when-cross-origin) to control "
        "how much referrer information is sent with requests.",
    ),
}


def check_security_headers(url: str, **kwargs: Any) -> list[dict]:
    """Return a list of findings for missing security headers.

    Each finding is a dict with keys: check, severity, detail, recommendation.
    """
    findings: list[dict] = []

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException as exc:
        findings.append(
            {
                "check": "security_headers",
                "severity": "low",
                "detail": f"Could not fetch URL: {exc}",
                "recommendation": "Ensure the target URL is reachable.",
            }
        )
        return findings

    response_headers = {k.lower(): v for k, v in resp.headers.items()}

    for header, (severity, recommendation) in EXPECTED_HEADERS.items():
        if header.lower() not in response_headers:
            findings.append(
                {
                    "check": "security_headers",
                    "severity": severity,
                    "detail": f"Missing header: {header}",
                    "recommendation": recommendation,
                }
            )

    if not findings:
        findings.append(
            {
                "check": "security_headers",
                "severity": "info",
                "detail": "All checked security headers are present.",
                "recommendation": "No action needed.",
            }
        )

    return findings
