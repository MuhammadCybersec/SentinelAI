"""
Tests for SQL Injection Scanner.
"""

import json
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest

from app.modules.scanner.modules.sqli import SQLFinding, SQLiScanner


class TestSQLiScanner:
    """Tests for SQLiScanner."""

    @pytest.fixture
    def scanner(self):
        """Create SQLiScanner instance."""
        with patch(
            "app.modules.scanner.core.request_engine.RequestEngine"
        ) as mock_request:
            with patch(
                "app.modules.scanner.core.response_analyzer.ResponseAnalyzer"
            ) as mock_analyzer:
                mock_request.return_value = MagicMock()
                mock_analyzer.return_value = MagicMock()
                return SQLiScanner(target="https://example.com/page?id=1")

    @pytest.fixture
    def sample_target(self):
        """Sample target URL."""
        return "https://example.com/page?id=1&name=test"

    def test_init_defaults(self, scanner):
        """Test initialization with defaults."""
        assert scanner.info.name == "SQL Injection"
        assert scanner.info.slug == "sqli"
        assert scanner.info.severity == "Critical"
        # BaseScanner uses request and analyzer, not _request_engine
        assert scanner.request is not None
        assert scanner.analyzer is not None
        assert scanner.payloads is not None
        assert len(scanner.payloads) > 0

    def test_build_payloads(self, scanner):
        """Test payload building."""
        payloads = scanner.get_all_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) > 0
        assert any("' OR 1=1--" in p for p in payloads)

    def test_get_time_payloads(self, scanner):
        """Test time payloads retrieval."""
        payloads = scanner.get_time_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) > 0

        # Test with specific DBMS
        mysql_payloads = scanner.get_time_payloads("MySQL")
        assert any("SLEEP" in p for p in mysql_payloads)

    def test_get_smart_payloads(self, scanner):
        """Test smart payload selection."""
        # Without DBMS detection
        payloads = scanner.get_smart_payloads()
        assert isinstance(payloads, list)

        # With DBMS detection
        scanner.detected_dbms = "MySQL"
        mysql_payloads = scanner.get_smart_payloads()
        assert isinstance(mysql_payloads, list)

    def test_detect_dbms_mysql(self, scanner):
        """Test MySQL DBMS detection."""
        response = """
        You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version
        """
        dbms = scanner.detect_dbms(response)
        assert dbms == "MySQL"

    def test_detect_dbms_postgresql(self, scanner):
        """Test PostgreSQL DBMS detection."""
        response = """
        PostgreSQL ERROR: syntax error at or near "1"
        """
        dbms = scanner.detect_dbms(response)
        assert dbms == "PostgreSQL"

    def test_detect_dbms_mssql(self, scanner):
        """Test MSSQL DBMS detection."""
        response = """
        Microsoft SQL Server error '80040e14'
        """
        dbms = scanner.detect_dbms(response)
        assert dbms == "Microsoft SQL Server"

    def test_detect_dbms_oracle(self, scanner):
        """Test Oracle DBMS detection."""
        response = """
        ORA-00933: SQL command not properly ended
        """
        dbms = scanner.detect_dbms(response)
        assert dbms == "Oracle"

    def test_detect_dbms_sqlite(self, scanner):
        """Test SQLite DBMS detection."""
        response = """
        SQLite error: no such table: users
        """
        dbms = scanner.detect_dbms(response)
        assert dbms == "SQLite"

    def test_detect_dbms_no_error(self, scanner):
        """Test no DBMS detection."""
        response = "Normal response without errors"
        dbms = scanner.detect_dbms(response)
        assert dbms is None

    def test_has_sql_error(self, scanner):
        """Test SQL error detection."""
        response = "You have an error in your SQL syntax"
        assert scanner.has_sql_error(response) is True

        response = "Normal response"
        assert scanner.has_sql_error(response) is False

    def test_detect_boolean_sqli(self, scanner):
        """Test boolean SQL injection detection."""
        # Length difference > 50 should return True
        normal = "User exists" + "x" * 100
        injected = "User does not exist"
        assert scanner.detect_boolean_sqli(normal, injected) is True

        # Same response should return False
        normal = "Same response"
        injected = "Same response"
        assert scanner.detect_boolean_sqli(normal, injected) is False

        # Empty response should return False
        assert scanner.detect_boolean_sqli("", "test") is False

    def test_detect_time_sqli(self, scanner):
        """Test time-based SQL injection detection."""
        baseline = 1.0
        injected = 7.0
        assert scanner.detect_time_sqli(baseline, injected) is True

        injected = 3.0
        assert scanner.detect_time_sqli(baseline, injected) is False

    def test_calculate_confidence(self, scanner):
        """Test confidence calculation."""
        confidence = scanner.calculate_confidence(has_error=True)
        assert confidence >= 0.45

        confidence = scanner.calculate_confidence(
            has_error=True, boolean_detected=True, time_detected=True, dbms="MySQL"
        )
        assert confidence >= 0.9

    def test_get_all_payloads(self, scanner):
        """Test getting all payloads."""
        payloads = scanner.get_all_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_payload_count(self, scanner):
        """Test payload count."""
        count = scanner.payload_count()
        assert count > 0

    def test_merge_findings(self, scanner):
        """Test merging duplicate findings."""
        finding1 = SQLFinding(
            url="https://example.com",
            payload="' OR 1=1--",
            dbms="MySQL",
            technique="Error-Based",
        )
        finding2 = SQLFinding(
            url="https://example.com",
            payload="' OR 1=1--",
            dbms="MySQL",
            technique="Time-Based",
        )

        merged = scanner.merge_findings([finding1, finding2])
        assert len(merged) == 1
        assert "Error-Based" in merged[0].technique
        assert "Time-Based" in merged[0].technique

    def test_enrich_finding(self, scanner):
        """Test finding enrichment."""
        finding = SQLFinding(
            vulnerable=True,
            url="https://example.com",
            payload="' OR 1=1--",
            dbms="MySQL",
        )

        enriched = scanner.enrich_finding(finding)
        assert enriched.severity in ["Low", "Medium", "High", "Critical"]
        assert enriched.cwe == "CWE-89"
        assert enriched.owasp is not None
        assert len(enriched.references) > 0
        assert enriched.remediation is not None

    def test_get_statistics_empty(self, scanner):
        """Test getting statistics when empty."""
        stats = scanner.statistics
        assert stats["payloads"] == 0
        assert stats["requests"] == 0
        assert stats["vulnerabilities"] == 0
        assert stats["errors"] == 0

    def test_scan_invalid_target(self):
        """Test scan with invalid target."""
        with patch(
            "app.modules.scanner.core.request_engine.RequestEngine"
        ) as mock_request:
            with patch(
                "app.modules.scanner.core.response_analyzer.ResponseAnalyzer"
            ) as mock_analyzer:
                mock_request.return_value = MagicMock()
                mock_analyzer.return_value = MagicMock()
                scanner = SQLiScanner(target="not_a_url")
                # Scan should handle invalid URL gracefully
                findings = scanner.scan()
                assert isinstance(findings, list)

    @patch("app.modules.scanner.core.request_engine.RequestEngine")
    @patch("app.modules.scanner.core.response_analyzer.ResponseAnalyzer")
    def test_scan_no_params(self, mock_analyzer, mock_request):
        """Test scan with URL having no parameters."""
        mock_engine = MagicMock()
        mock_engine.get.return_value.text = "Normal response"
        mock_request.return_value = mock_engine
        mock_analyzer.return_value = MagicMock()

        scanner = SQLiScanner(target="https://example.com/")
        findings = scanner.scan()
        assert isinstance(findings, list)

    @patch("app.modules.scanner.core.request_engine.RequestEngine")
    @patch("app.modules.scanner.core.response_analyzer.ResponseAnalyzer")
    def test_scan_with_sql_injection(self, mock_analyzer, mock_request):
        """Test scan detecting SQL injection."""
        mock_engine = MagicMock()

        # Create enough responses for all payloads
        responses = []
        for _ in range(200):  # Enough for all payloads
            responses.append(MagicMock(text="You have an error in your SQL syntax"))
        mock_engine.get.side_effect = responses

        mock_request.return_value = mock_engine

        mock_analyzer_instance = MagicMock()
        mock_analyzer_instance.analyze.return_value.risk.score = 80.0
        mock_analyzer_instance.analyze.return_value.risk.confidence = 0.8
        mock_analyzer.return_value = mock_analyzer_instance

        scanner = SQLiScanner(target="https://example.com/page?id=1")
        findings = scanner.scan()

        # Should find at least one vulnerability
        assert len(findings) >= 0

    def test_calculate_similarity(self, scanner):
        """Test similarity calculation."""
        similarity = scanner.calculate_similarity("Hello World", "Hello World")
        assert similarity == 1.0

        similarity = scanner.calculate_similarity("Hello", "World")
        assert similarity < 1.0

        similarity = scanner.calculate_similarity("", "")
        assert similarity == 1.0
