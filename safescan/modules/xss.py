"""Reflected XSS probe module.

Sends a benign canary string in a user-supplied parameter and checks whether
it is reflected verbatim in the response body.  This is **non-destructive** —
no actual exploit payload is used.
"""

from __future__ import annotations
from typing import Any
import uuid

import requests

# A clearly harmless canary that is extremely unlikely to already appear on the page.
CANARY = f"safescan-xss-{uuid.uuid4().hex[:8]}"


def check_reflected_xss(url: str, *, param: str | None = None, **kwargs: Any) -> list[dict]:
    """Probe for reflected XSS by injecting a canary into *param*.

    If *param* is ``None`` the check is skipped (no parameter to test).
    """
    findings: list[dict] = []

    if param is None:
        findings.append(
            {
                "check": "reflected_xss",
                "severity": "info",
                "detail": "No test parameter supplied — skipping reflected XSS probe.",
                "recommendation": "Re-run with --param <name> to test a specific query parameter.",
            }
        )
        return findings

    test_url = f"{url.rstrip('/')}?{param}={CANARY}"

    try:
        resp = requests.get(test_url, timeout=10, allow_redirects=True)
    except requests.RequestException as exc:
        findings.append(
            {
                "check": "reflected_xss",
                "severity": "low",
                "detail": f"Could not reach URL for XSS probe: {exc}",
                "recommendation": "Ensure the target URL is reachable.",
            }
        )
        return findings

    if CANARY in resp.text:
        findings.append(
            {
                "check": "reflected_xss",
                "severity": "high",
                "detail": (
                    f"Canary string reflected in response when injected via "
                    f"parameter '{param}'. This may indicate a reflected XSS vulnerability."
                ),
                "recommendation": (
                    "Sanitize and encode all user input before rendering it in HTML. "
                    "Use context-aware output encoding and consider a strong Content-Security-Policy."
                ),
            }
        )
    else:
        findings.append(
            {
                "check": "reflected_xss",
                "severity": "info",
                "detail": f"Canary was not reflected via parameter '{param}'.",
                "recommendation": "No action needed for this parameter.",
            }
        )

    return findings
