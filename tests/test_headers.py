"""Tests for safescan.modules.headers using pytest + responses mock."""

from __future__ import annotations

import responses
import pytest

from safescan.modules.headers import check_security_headers, EXPECTED_HEADERS


TARGET = "https://example-test-target.local"


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _mock_response(headers: dict[str, str] | None = None, status: int = 200) -> None:
    """Register a mocked GET response on the TARGET URL."""
    responses.add(
        responses.GET,
        TARGET,
        body="<html></html>",
        headers=headers or {},
        status=status,
    )


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestSecurityHeaders:
    """Unit tests for the security-headers check module."""

    @responses.activate
    def test_all_headers_missing(self) -> None:
        """When no security headers are present, every expected header should be flagged."""
        _mock_response(headers={})
        findings = check_security_headers(TARGET)

        missing_headers = {f["detail"] for f in findings}
        for header in EXPECTED_HEADERS:
            assert f"Missing header: {header}" in missing_headers, (
                f"Expected '{header}' to be flagged as missing"
            )

    @responses.activate
    def test_all_headers_present(self) -> None:
        """When every expected header exists the only finding should be informational."""
        good_headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=63072000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        _mock_response(headers=good_headers)
        findings = check_security_headers(TARGET)

        assert len(findings) == 1
        assert findings[0]["severity"] == "info"
        assert "All checked security headers are present" in findings[0]["detail"]

    @responses.activate
    def test_partial_headers(self) -> None:
        """When some headers are missing, only those should appear."""
        partial_headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        }
        _mock_response(headers=partial_headers)
        findings = check_security_headers(TARGET)

        flagged = {f["detail"] for f in findings}
        # These should be present → NOT flagged
        assert "Missing header: Content-Security-Policy" not in flagged
        assert "Missing header: X-Content-Type-Options" not in flagged
        # These should be missing → flagged
        assert "Missing header: Strict-Transport-Security" in flagged
        assert "Missing header: X-Frame-Options" in flagged
        assert "Missing header: Referrer-Policy" in flagged

    @responses.activate
    def test_severity_levels(self) -> None:
        """Severity values must match EXPECTED_HEADERS definitions."""
        _mock_response(headers={})
        findings = check_security_headers(TARGET)

        for f in findings:
            header_name = f["detail"].replace("Missing header: ", "")
            if header_name in EXPECTED_HEADERS:
                expected_severity, _ = EXPECTED_HEADERS[header_name]
                assert f["severity"] == expected_severity, (
                    f"{header_name}: expected severity '{expected_severity}', got '{f['severity']}'"
                )

    @responses.activate
    def test_recommendation_present(self) -> None:
        """Every finding must include a non-empty recommendation."""
        _mock_response(headers={})
        findings = check_security_headers(TARGET)

        for f in findings:
            assert "recommendation" in f
            assert len(f["recommendation"]) > 0

    @responses.activate
    def test_unreachable_target(self) -> None:
        """When the target is unreachable we should get a graceful error finding."""
        # Don't register any mock → requests will raise ConnectionError.
        findings = check_security_headers("https://unreachable.invalid")

        assert len(findings) == 1
        assert findings[0]["severity"] == "low"
        assert "Could not fetch URL" in findings[0]["detail"]

    @responses.activate
    def test_case_insensitive_header_matching(self) -> None:
        """Header lookup should be case-insensitive (web servers may vary case)."""
        headers = {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=63072000",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        }
        _mock_response(headers=headers)
        findings = check_security_headers(TARGET)

        assert len(findings) == 1
        assert findings[0]["severity"] == "info"
