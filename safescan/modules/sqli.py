"""SQL-injection heuristic module.

Sends common *error-triggering* payloads (a single quote, etc.) through a
user-supplied parameter and inspects the response for database error strings.

This is **safe / non-destructive** — no data is modified, no exploitation
is attempted.  It is a detection-only heuristic.
"""

from __future__ import annotations
from typing import Any
from urllib.parse import quote
import re

import requests

# Payloads designed to trigger DB errors without altering data.
SQLI_PAYLOADS: list[str] = [
    "'",
    "1' OR '1'='1",
    "1; --",
    "' OR ''='",
]

# Regex patterns that indicate a database error message in the response body.
ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning:.*mysql_", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"microsoft ole db provider for sql server", re.I),
    re.compile(r"pg_query\(\):.*error", re.I),
    re.compile(r"supplied argument is not a valid .* result", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"SQLite3::SQLException", re.I),
    re.compile(r"SQLSTATE\[", re.I),
]


def check_sqli(url: str, *, param: str | None = None, **kwargs: Any) -> list[dict]:
    """Probe for SQL injection by sending error-triggering payloads via *param*.

    If *param* is ``None`` the check is skipped.
    """
    findings: list[dict] = []

    if param is None:
        findings.append(
            {
                "check": "sqli",
                "severity": "info",
                "detail": "No test parameter supplied — skipping SQLi probe.",
                "recommendation": "Re-run with --param <name> to test a specific query parameter.",
            }
        )
        return findings

    detected = False

    for payload in SQLI_PAYLOADS:
        test_url = f"{url.rstrip('/')}?{param}={quote(payload)}"

        try:
            resp = requests.get(test_url, timeout=10, allow_redirects=True)
        except requests.RequestException:
            continue

        for pattern in ERROR_PATTERNS:
            if pattern.search(resp.text):
                findings.append(
                    {
                        "check": "sqli",
                        "severity": "high",
                        "detail": (
                            f"Possible SQL injection: database error detected when "
                            f"sending payload '{payload}' via parameter '{param}'."
                        ),
                        "recommendation": (
                            "Use parameterized queries (prepared statements) for all "
                            "database access. Never concatenate user input into SQL strings."
                        ),
                    }
                )
                detected = True
                break  # one match per payload is enough

    if not detected:
        findings.append(
            {
                "check": "sqli",
                "severity": "info",
                "detail": f"No SQL error signatures detected via parameter '{param}'.",
                "recommendation": "No action needed for this parameter.",
            }
        )

    return findings
