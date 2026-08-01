"""
Unit tests for XSS Scanner.
"""

from unittest.mock import Mock, patch

import pytest

from app.modules.scanner.modules.xss_scanner import (
    LegacyXSSScanner,
    XSSScanner,
)


class TestXSSScanner:
    """Tests for XSSScanner."""

    def test_initialization(self) -> None:
        """Test scanner initialization."""
        scanner = XSSScanner("https://example.com")
        assert scanner.target == "https://example.com"
        assert len(scanner.payloads) > 0
        assert scanner.version == "2.0.0"

    def test_check_reflection(self) -> None:
        """Test reflection detection."""
        scanner = XSSScanner("https://example.com")
        payload = "<script>alert('XSS')</script>"

        # Test exact match
        response = f"Response with {payload} in it"
        assert scanner._check_reflection(payload, response) is True

        # Test no match
        response = "No payload here"
        assert scanner._check_reflection(payload, response) is False

    def test_check_execution(self) -> None:
        """Test execution detection."""
        scanner = XSSScanner("https://example.com")

        # Test with alert
        response = "alert('XSS')"
        assert scanner._check_execution("<script>", response) is True

        # Test with onerror
        response = 'onerror="alert"'
        assert scanner._check_execution("<img>", response) is True

    def test_check_dom_vulnerability(self) -> None:
        """Test DOM vulnerability detection."""
        scanner = XSSScanner("https://example.com")

        # Test with DOM indicator
        response = "document.write(userInput)"
        assert scanner._check_dom_vulnerability(response) is True

        # Test without DOM indicator
        response = "console.log('safe')"
        assert scanner._check_dom_vulnerability(response) is False

    def test_create_xss_finding(self) -> None:
        """Test XSS finding creation."""
        scanner = XSSScanner("https://example.com")

        scanner._create_xss_finding(
            url="https://example.com/test",
            parameter="q",
            payload="<script>",
            evidence="Response with <script>",
            vulnerability_type="reflected_xss",
            severity="high",
            confidence=0.80,
            status_code=200,
            response_time=0.5,
            description="XSS vulnerability found",
            remediation="Encode output",
        )

        assert len(scanner.findings) == 1
        finding = scanner.findings[0]
        assert finding.vulnerability_type == "reflected_xss"
        assert finding.severity == "high"
        assert finding.confidence == 80.0
        assert finding.parameter == "q"
        assert finding.payload == "<script>"

    @patch("app.modules.scanner.modules.xss_scanner.XSSScanner.safe_get")
    def test_test_payload_reflected(self, mock_get) -> None:
        """Test payload testing with reflection."""
        scanner = XSSScanner("https://example.com")

        # Mock response with reflected payload
        # Use 'body' instead of 'text' because ResponseData uses 'body'
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.body = "Response with <script>alert('XSS')</script>"
        mock_get.return_value = mock_response

        scanner._test_payload(
            url="https://example.com/test?q=test",
            parameter="q",
            payload="<script>alert('XSS')</script>",
            original_values=["test"],
        )

        # Should create a finding
        assert len(scanner.findings) >= 1

        if scanner.findings:
            finding = scanner.findings[0]
            assert finding.vulnerability_type == "reflected_xss"
            assert finding.severity == "high"
            # Since the payload is executed (alert pattern detected), confidence is 95%
            assert finding.confidence == 95.0

    @patch("app.modules.scanner.modules.xss_scanner.XSSScanner.safe_get")
    def test_test_payload_no_reflection(self, mock_get) -> None:
        """Test payload testing with no reflection."""
        scanner = XSSScanner("https://example.com")

        # Mock response without payload
        # Use 'body' instead of 'text'
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.body = "No payload here"
        mock_get.return_value = mock_response

        scanner._test_payload(
            url="https://example.com/test?q=test",
            parameter="q",
            payload="<script>alert('XSS')</script>",
            original_values=["test"],
        )

        # Should not create a finding
        assert len(scanner.findings) == 0

    def test_get_remediation(self) -> None:
        """Test remediation generation."""
        scanner = XSSScanner("https://example.com")
        remediation = scanner._get_remediation("q")

        assert "Input Validation" in remediation
        assert "Output Encoding" in remediation
        assert "parameter" in remediation

    def test_get_dom_remediation(self) -> None:
        """Test DOM remediation generation."""
        scanner = XSSScanner("https://example.com")
        remediation = scanner._get_dom_remediation()

        assert "eval()" in remediation
        assert "innerHTML" in remediation
        assert "DOMPurify" in remediation

    def test_get_statistics(self) -> None:
        """Test statistics generation."""
        scanner = XSSScanner("https://example.com")

        # Add findings
        scanner._create_xss_finding(
            url="https://example.com/test1",
            parameter="q",
            payload="<script>",
            evidence="test",
            vulnerability_type="reflected_xss",
            severity="high",
            confidence=0.80,
            status_code=200,
            response_time=0.5,
            description="Test",
            remediation="Test",
        )

        stats = scanner.get_statistics()
        assert stats["xss_types"]["reflected"] == 1
        assert stats["findings"] == 1

    def test_legacy_compatibility(self) -> None:
        """Test legacy scanner compatibility."""
        scanner = LegacyXSSScanner("https://example.com")
        assert isinstance(scanner, XSSScanner)

        # Legacy scan should return dicts
        with patch.object(scanner, "run") as mock_run:
            mock_run.return_value = []
            results = scanner.scan()
            assert isinstance(results, list)


class TestXSSScannerIntegration:
    """Integration tests for XSS Scanner."""

    @patch("app.modules.scanner.modules.xss_scanner.XSSScanner.safe_get")
    def test_full_scan(self, mock_get) -> None:
        """Test full scan workflow."""
        scanner = XSSScanner("https://example.com")

        # Mock responses
        # Use 'body' instead of 'text'
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.body = """
        <html>
            <a href="/search?q=test">Search</a>
            <form action="/search"><input name="q"></form>
            <script>document.write(location.search)</script>
        </html>
        """
        mock_get.return_value = mock_response

        results = scanner.run()

        # Should complete without errors
        assert isinstance(results, list)
        assert scanner.status.value == "finished"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
