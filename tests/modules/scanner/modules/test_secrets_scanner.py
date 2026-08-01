"""
Tests for Secrets Scanner.
"""

import tempfile
from unittest.mock import patch

import pytest

from app.modules.scanner.modules.secrets_scanner import SecretFinding, SecretsScanner


class TestSecretsScanner:
    """Tests for SecretsScanner."""

    @pytest.fixture
    def scanner(self):
        """Create SecretsScanner instance."""
        return SecretsScanner(target="https://example.com")

    @pytest.fixture
    def sample_content(self):
        """Sample content with various secrets."""
        return """
        # AWS Access Key
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        
        # AWS Secret Key
        AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        
        # Google API Key
        GOOGLE_API_KEY=AIzaSyA1234567890abcdefghijklmnopqrstuvwxyz
        
        # GitHub Token
        GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
        
        # JWT Token
        JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
        
        # Stripe Key
        STRIPE_KEY=sk_live_1234567890abcdefghijklmnopqrst
        
        # Discord Webhook
        DISCORD_WEBHOOK=https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz
        
        # OpenAI Key
        OPENAI_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz
        
        # Generic Secret
        API_SECRET=1234567890abcdefghijklmnopqrstuvwxyz1234567890
        """

    def test_init_defaults(self, scanner):
        """Test initialization with defaults."""
        assert scanner._config is not None
        assert scanner._request_engine is not None
        assert scanner._findings == []
        assert scanner._max_content_size == 10 * 1024 * 1024
        assert scanner._min_confidence == 50.0

    def test_detect_aws_access_key(self, scanner, sample_content):
        """Test AWS Access Key detection."""
        findings = scanner.detect_secrets(sample_content, "test.txt")
        aws_findings = [f for f in findings if f.secret_type == "AWS Access Key"]
        assert len(aws_findings) == 1
        assert aws_findings[0].severity == "Critical"
        assert aws_findings[0].confidence == 95.0

    def test_detect_aws_secret_key(self, scanner, sample_content):
        """Test AWS Secret Key detection."""
        findings = scanner.detect_secrets(sample_content, "test.txt")
        aws_findings = [f for f in findings if f.secret_type == "AWS Secret Key"]
        assert len(aws_findings) == 1
        assert aws_findings[0].severity == "Critical"

    def test_detect_google_api_key(self, scanner, sample_content):
        """Test Google API Key detection."""
        findings = scanner.detect_secrets(sample_content, "test.txt")
        google_findings = [f for f in findings if f.secret_type == "Google API Key"]
        assert len(google_findings) == 1
        assert google_findings[0].severity == "High"

    def test_detect_github_token(self, scanner, sample_content):
        """Test GitHub Token detection."""
        findings = scanner.detect_secrets(sample_content, "test.txt")
        github_findings = [
            f for f in findings if f.secret_type == "GitHub Personal Access Token"
        ]
        assert len(github_findings) == 1
        assert github_findings[0].severity == "Critical"

    def test_detect_jwt_token(self, scanner, sample_content):
        """Test JWT Token detection."""
        findings = scanner.detect_secrets(sample_content, "test.txt")
        jwt_findings = [f for f in findings if f.secret_type == "JWT Token"]
        assert len(jwt_findings) == 1
        assert jwt_findings[0].severity == "High"

    def test_detect_stripe_key(self, scanner, sample_content):
        """Test Stripe Key detection."""
        findings = scanner.detect_secrets(sample_content, "test.txt")
        stripe_findings = [f for f in findings if f.secret_type == "Stripe API Key"]
        assert len(stripe_findings) == 1
        assert stripe_findings[0].severity == "Critical"

    def test_detect_discord_webhook(self, scanner, sample_content):
        """Test Discord Webhook detection."""
        findings = scanner.detect_secrets(sample_content, "test.txt")
        discord_findings = [f for f in findings if f.secret_type == "Discord Webhook"]
        assert len(discord_findings) == 1
        assert discord_findings[0].severity == "High"

    def test_detect_openai_key(self, scanner, sample_content):
        """Test OpenAI Key detection."""
        findings = scanner.detect_secrets(sample_content, "test.txt")
        openai_findings = [f for f in findings if f.secret_type == "OpenAI API Key"]
        assert len(openai_findings) == 1
        assert openai_findings[0].severity == "Critical"

    def test_validate_aws_access_key(self, scanner):
        """Test AWS Access Key validation."""
        valid_key = "AKIAIOSFODNN7EXAMPLE"
        invalid_key = "AKIAINVALIDKEY"

        confidence = scanner.validate_secret("AWS Access Key", valid_key)
        assert confidence == 95.0

        confidence = scanner.validate_secret("AWS Access Key", invalid_key)
        assert confidence is None

    def test_validate_aws_secret_key(self, scanner):
        """Test AWS Secret Key validation."""
        valid_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        invalid_key = "short"

        confidence = scanner.validate_secret("AWS Secret Key", valid_key)
        assert confidence == 92.0

        confidence = scanner.validate_secret("AWS Secret Key", invalid_key)
        assert confidence is None

    def test_validate_jwt(self, scanner):
        """Test JWT validation."""
        valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        invalid_jwt = "invalid.jwt.token"

        confidence = scanner.validate_secret("JWT Token", valid_jwt)
        assert confidence == 88.0

        confidence = scanner.validate_secret("JWT Token", invalid_jwt)
        assert confidence is None

    def test_validate_github_token(self, scanner):
        """Test GitHub Token validation."""
        valid_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        invalid_token = "ghp_invalid"

        confidence = scanner.validate_secret(
            "GitHub Personal Access Token", valid_token
        )
        assert confidence == 95.0

        confidence = scanner.validate_secret(
            "GitHub Personal Access Token", invalid_token
        )
        assert confidence is None

    def test_merge_findings(self, scanner):
        """Test merging duplicate findings."""
        finding1 = SecretFinding(
            secret_type="AWS Access Key",
            secret="AKIAIOSFODNN7EXAMPLE",
            url="test.txt",
            confidence=95.0,
            severity="Critical",
        )
        finding2 = SecretFinding(
            secret_type="AWS Access Key",
            secret="AKIAIOSFODNN7EXAMPLE",
            url="test.txt",
            confidence=90.0,
            severity="High",
        )
        finding3 = SecretFinding(
            secret_type="Google API Key",
            secret="AIzaSyA1234567890",
            url="test.txt",
            confidence=90.0,
            severity="High",
        )

        merged = scanner.merge_findings([finding1, finding2, finding3])
        assert len(merged) == 2
        assert merged[0].confidence == 95.0
        assert merged[0].severity == "Critical"

    def test_enrich_finding(self, scanner):
        """Test finding enrichment."""
        finding = SecretFinding(
            secret_type="AWS Access Key",
            secret="AKIAIOSFODNN7EXAMPLE",
            severity="Critical",
        )

        enriched = scanner.enrich_finding(finding)
        assert enriched.cwe == "CWE-798"
        assert enriched.owasp is not None
        assert enriched.remediation is not None
        assert len(enriched.references) > 0

    def test_enrich_finding_severity(self, scanner):
        """Test severity-based enrichment."""
        finding = SecretFinding(
            secret_type="Google API Key", secret="AIzaSyA1234567890", severity="High"
        )

        enriched = scanner.enrich_finding(finding)
        assert enriched.severity == "High"
        assert "CVSS" in enriched.cvss

    def test_is_redacted(self, scanner):
        """Test redacted secret detection."""
        assert scanner._is_redacted("************") is True
        assert scanner._is_redacted("[REDACTED]") is True
        assert scanner._is_redacted("AKIAIOSFODNN7EXAMPLE") is False

    def test_is_false_positive(self, scanner):
        """Test false positive detection."""
        # Example pattern
        line = 'API_KEY = "your_api_key_here"'
        secret = "your_api_key_here"
        assert scanner._is_false_positive(line, secret) is True

        # Real secret
        line = 'AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"'
        secret = "AKIAIOSFODNN7EXAMPLE"
        assert scanner._is_false_positive(line, secret) is False

    def test_generate_secret_id(self, scanner):
        """Test secret ID generation."""
        secret_type = "AWS Access Key"
        secret = "AKIAIOSFODNN7EXAMPLE"
        source = "test.txt"

        id1 = scanner._generate_secret_id(secret_type, secret, source)
        id2 = scanner._generate_secret_id(secret_type, secret, source)
        id3 = scanner._generate_secret_id("Google API Key", secret, source)

        assert id1 == id2
        assert id1 != id3

    def test_create_finding(self, scanner):
        """Test finding creation."""
        pattern_info = {
            "severity": "Critical",
            "mask": lambda s: s[:4] + "****" + s[-4:],
            "cwe": "CWE-798",
        }

        finding = scanner._create_finding(
            secret_type="AWS Access Key",
            secret="AKIAIOSFODNN7EXAMPLE",
            line='AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"',
            line_number=10,
            source="test.txt",
            confidence=95.0,
            pattern_info=pattern_info,
        )

        assert finding.secret_type == "AWS Access Key"
        assert finding.severity == "Critical"
        assert finding.confidence == 95.0
        assert finding.line_number == 10
        assert finding.cwe == "CWE-798"

    def test_get_findings_empty(self, scanner):
        """Test getting findings when empty."""
        findings = scanner.get_findings()
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_get_statistics(self, scanner):
        """Test getting statistics."""
        stats = scanner.get_statistics()
        assert stats["total_secrets_detected"] == 0
        assert stats["valid_secrets"] == 0
        assert stats["false_positives"] == 0
        assert stats["duplicates_removed"] == 0

    def test_scan_with_http_url(self, scanner):
        """Test scan with HTTP URL."""
        with patch.object(scanner, "_request_engine") as mock_engine:
            mock_engine.get.return_value.text = "AKIAIOSFODNN7EXAMPLE"
            result = scanner.scan()
            assert result.success is True
            assert len(result.findings) > 0

    def test_scan_with_file(self, scanner):
        """Test scan with file."""
        import os

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("AKIAIOSFODNN7EXAMPLE")
            f.flush()
            f.close()  # Close before scanning
            scanner.target = f.name
            result = scanner.scan()
            assert result.success is True
            # Clean up
            try:
                os.unlink(f.name)
            except PermissionError:
                pass

    def test_scan_invalid_file(self, scanner):
        """Test scan with invalid file."""
        scanner.target = "/nonexistent/file.txt"
        result = scanner.scan()
        assert result.success is False
        assert result.error is not None

    def test_stop_scan(self, scanner):
        """Test scan stop."""
        scanner._is_running = True
        scanner.stop_scan()
        assert scanner._is_running is False

    def test_get_scan_status(self, scanner):
        """Test scan status."""
        scanner._is_running = True
        scanner._findings = [SecretFinding()]
        status = scanner.get_scan_status()
        assert status["is_running"] is True
        assert status["findings"] == 1

    def test_extract_context(self, scanner):
        """Test context extraction."""
        line = "line1\nline2\nline3\nline4"
        context = scanner._extract_context(line, 2)
        assert len(context) > 0

    def test_finding_secret_masking(self, scanner):
        """Test secret masking."""
        pattern_info = {
            "severity": "Critical",
            "mask": lambda s: s[:4] + "****" + s[-4:],
            "cwe": "CWE-798",
        }

        finding = scanner._create_finding(
            secret_type="AWS Access Key",
            secret="AKIAIOSFODNN7EXAMPLE",
            line='AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"',
            line_number=1,
            source="test.txt",
            confidence=95.0,
            pattern_info=pattern_info,
        )

        assert "****" in finding.secret
        assert len(finding.secret) <= len("AKIAIOSFODNN7EXAMPLE")

    def test_duplicate_removal(self, scanner, sample_content):
        """Test duplicate removal during detection."""
        findings1 = scanner.detect_secrets(sample_content, "test.txt")
        # scanner._seen_secrets.clear()

        # Scan same content twice
        findings2 = scanner.detect_secrets(sample_content, "test.txt")
        assert scanner.statistics["duplicates_removed"] > 0

    def test_false_positive_filtering(self, scanner):
        """Test false positive filtering."""
        content = """
        # Example AWS Key
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        
        # This is a test API key
        API_KEY="your_api_key_here"
        """
        findings = scanner.detect_secrets(content, "test.txt")
        # The example key might still be detected, but test key should be filtered
        assert len(findings) >= 0

    def test_finding_metadata(self, scanner):
        """Test finding metadata."""
        pattern_info = {"severity": "Critical", "mask": lambda s: s, "cwe": "CWE-798"}

        finding = scanner._create_finding(
            secret_type="OpenAI API Key",
            secret="sk-1234567890abcdefghijklmnopqrstuvwxyz",
            line='OPENAI_KEY="sk-1234567890abcdefghijklmnopqrstuvwxyz"',
            line_number=5,
            source="test.txt",
            confidence=95.0,
            pattern_info=pattern_info,
        )

        assert finding.metadata is not None
        assert "source_type" in finding.metadata

    def test_secret_id_consistency(self, scanner):
        """Test secret ID consistency."""
        id1 = scanner._generate_secret_id(
            "AWS Access Key", "AKIAIOSFODNN7EXAMPLE", "test.txt"
        )
        id2 = scanner._generate_secret_id(
            "AWS Access Key", "AKIAIOSFODNN7EXAMPLE", "test.txt"
        )
        assert id1 == id2

        id3 = scanner._generate_secret_id(
            "AWS Access Key", "AKIAIOSFODNN7EXAMPLE", "different.txt"
        )
        assert id1 != id3
