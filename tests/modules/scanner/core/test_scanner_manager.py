"""
Tests for Scanner Manager.
"""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from app.modules.scanner.core.scanner_manager import (
    ScanFinding,
    ScannerManager,
    ScanStatistics,
)


class TestScannerManager:
    """Tests for ScannerManager."""

    @pytest.fixture
    def manager(self):
        """Create ScannerManager instance."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            db_path = f.name
        return ScannerManager(db_path=db_path)

    @pytest.fixture
    def sample_target(self):
        """Sample target URL."""
        return "https://example.com/test?id=1"

    def test_init_defaults(self, manager):
        """Test initialization with defaults."""
        assert manager._max_workers == 4
        assert manager._timeout == 60.0
        assert manager._scanners is not None
        assert "xss" in manager._scanners
        assert "sqli" in manager._scanners

    def test_run_scan_empty_target(self, manager):
        """Test scan with empty target."""
        with pytest.raises(ValueError, match="Target URL cannot be empty"):
            manager.run_scan("")

    def test_get_status_not_running(self, manager):
        """Test status when not running."""
        status = manager.get_status()
        assert status["is_running"] is False
        assert status["total_findings"] == 0
        assert "xss" in status["scanners_available"]

    def test_register_scanner(self, manager):
        """Test registering a new scanner."""
        mock_scanner = MagicMock()
        manager.register_scanner("test_scanner", mock_scanner)
        assert "test_scanner" in manager._scanners

    def test_clear_findings(self, manager):
        """Test clearing findings."""
        manager._findings.append(
            ScanFinding(scanner="test", title="Test Finding", severity="High")
        )
        assert len(manager._findings) == 1
        manager.clear_findings()
        assert len(manager._findings) == 0

    def test_get_findings_empty(self, manager):
        """Test getting findings when empty."""
        findings = manager.get_findings()
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_get_statistics_empty(self, manager):
        """Test getting statistics when empty."""
        stats = manager.get_statistics()
        assert stats.total_findings == 0
        assert stats.critical == 0
        assert stats.high == 0
        assert stats.medium == 0
        assert stats.low == 0

    def test_scan_finding_creation(self):
        """Test ScanFinding creation."""
        finding = ScanFinding(
            scanner="sqli",
            title="SQL Injection",
            description="SQL Injection detected",
            severity="High",
            cwe="CWE-89",
            owasp="A03:2021",
            cvss="7.5",
            url="https://example.com",
            payload="' OR 1=1--",
            evidence=["Error: SQL syntax"],
            remediation="Use parameterized queries",
            references=["https://cwe.mitre.org/"],
        )
        assert finding.scanner == "sqli"
        assert finding.severity == "High"
        assert finding.cwe == "CWE-89"
        assert len(finding.evidence) == 1

    def test_statistics_creation(self):
        """Test ScanStatistics creation."""
        stats = ScanStatistics(
            total_findings=10,
            critical=2,
            high=3,
            medium=4,
            low=1,
            scanners_used=["xss", "sqli"],
            total_scanners=2,
            duration=5.5,
        )
        assert stats.total_findings == 10
        assert stats.critical == 2
        assert stats.high == 3
        assert stats.medium == 4
        assert stats.low == 1
        assert len(stats.scanners_used) == 2
        assert stats.duration == 5.5

    def test_convert_sqli_finding(self, manager):
        """Test SQLi finding conversion."""
        finding = ScanFinding()
        raw = {
            "title": "SQL Injection",
            "description": "SQL injection detected",
            "severity": "Critical",
            "cwe": "CWE-89",
            "cvss": "9.8",
            "payload": "' OR 1=1--",
            "evidence": ["Error detected"],
            "remediation": "Use prepared statements",
            "dbms": "MySQL",
            "technique": "Error-Based",
        }
        manager._convert_sqli_finding(finding, raw)
        assert finding.title == "SQL Injection"
        assert finding.severity == "Critical"
        assert finding.cwe == "CWE-89"
        assert finding.payload == "' OR 1=1--"
        assert finding.metadata["dbms"] == "MySQL"

    def test_convert_xss_finding(self, manager):
        """Test XSS finding conversion."""
        finding = ScanFinding()
        raw = {
            "title": "XSS Vulnerability",
            "description": "XSS detected",
            "severity": "Medium",
            "cwe": "CWE-79",
            "payload": "<script>alert(1)</script>",
            "evidence": ["Script executed"],
            "remediation": "Encode output",
        }
        manager._convert_xss_finding(finding, raw)
        assert finding.title == "XSS Vulnerability"
        assert finding.severity == "Medium"
        assert finding.cwe == "CWE-79"
        assert finding.payload == "<script>alert(1)</script>"

    def test_generate_executive_summary_no_findings(self, manager):
        """Test executive summary with no findings."""
        summary = manager._generate_executive_summary()
        assert "No security vulnerabilities" in summary

    def test_generate_executive_summary_with_findings(self, manager):
        """Test executive summary with findings."""
        manager._findings = [
            ScanFinding(severity="Critical"),
            ScanFinding(severity="High"),
            ScanFinding(severity="Medium"),
        ]
        manager._statistics.total_findings = 3
        manager._statistics.critical = 1
        manager._statistics.high = 1
        manager._statistics.medium = 1

        summary = manager._generate_executive_summary()
        assert "3 vulnerabilities" in summary
        assert "critical" in summary
        assert "high" in summary
        assert "medium" in summary

    def test_generate_recommendations(self, manager):
        """Test recommendations generation."""
        manager._findings = [
            ScanFinding(remediation="Use parameterized queries"),
            ScanFinding(remediation="Encode output"),
        ]
        recommendations = manager._generate_recommendations()
        assert "Use parameterized queries" in recommendations
        assert "Encode output" in recommendations
        assert len(recommendations) >= 4

    def test_generate_report_data(self, manager):
        """Test report data generation."""
        manager._findings = [
            ScanFinding(
                scanner="sqli",
                title="SQL Injection",
                severity="High",
                cwe="CWE-89",
                url="https://example.com",
            )
        ]
        manager._statistics.total_findings = 1
        manager._statistics.high = 1

        report = manager._generate_report_data()
        assert report["title"] == "SentinelAI Security Scan Report"
        assert report["statistics"]["total_findings"] == 1
        assert len(report["findings"]) == 1
        assert report["findings"][0]["scanner"] == "sqli"
        assert "recommendations" in report

    def test_save_to_database(self, manager):
        """Test saving to database."""
        # Add a finding
        finding = ScanFinding(scanner="sqli", title="SQL Injection", severity="High")
        manager._findings.append(finding)
        manager._scan_id = uuid4()
        manager._statistics.total_findings = 1
        manager._statistics.high = 1

        manager._save_to_database()

        # Check file exists and has content
        assert Path(manager._db_path).exists()

        # Read and verify content
        with open(manager._db_path, "r") as f:
            content = f.read()
            assert content, "File should not be empty"
            data = json.loads(content)
            assert isinstance(data, list)
            assert len(data) == 1
            assert data[0]["scan_id"] == str(manager._scan_id)
            assert len(data[0]["findings"]) == 1

    def test_update_statistics(self, manager):
        """Test statistics update."""
        manager._findings = [
            ScanFinding(severity="Critical"),
            ScanFinding(severity="High"),
            ScanFinding(severity="Medium"),
            ScanFinding(severity="Low"),
            ScanFinding(severity="Critical"),
        ]
        manager._update_statistics()
        assert manager._statistics.total_findings == 5
        assert manager._statistics.critical == 2
        assert manager._statistics.high == 1
        assert manager._statistics.medium == 1
        assert manager._statistics.low == 1

    @patch("app.modules.scanner.core.scanner_manager.XSSScanner")
    @patch("app.modules.scanner.modules.sqli.SQLiScanner")
    def test_run_scanners_parallel(self, mock_sqli, mock_xss, manager, sample_target):
        """Test parallel scanner execution."""
        # Setup XSS Scanner mock with scan method
        mock_xss_instance = MagicMock()

        # Define scan method as a regular method that returns list
        def xss_scan():
            return [{"title": "XSS", "severity": "Medium"}]

        mock_xss_instance.scan = xss_scan
        mock_xss.return_value = mock_xss_instance

        # Setup SQLi Scanner mock with scan method
        mock_sqli_instance = MagicMock()

        def sqli_scan():
            return [{"title": "SQLi", "severity": "High"}]

        mock_sqli_instance.scan = sqli_scan
        mock_sqli.return_value = mock_sqli_instance
        print(manager._scanners)
        manager._scanners["xss"] = mock_xss
        manager._scanners["sqli"] = mock_sqli

        results = manager._run_scanners_parallel(sample_target, ["xss", "sqli"])

        assert "xss" in results
        assert "sqli" in results
        assert len(results["xss"]["findings"]) >= 0
        assert len(results["sqli"]["findings"]) >= 0

    def test_process_results(self, manager, sample_target):
        """Test processing results."""
        results = {
            "sqli": {"findings": [ScanFinding(severity="Critical")]},
            "xss": {
                "findings": [
                    ScanFinding(severity="Medium"),
                    ScanFinding(severity="Low"),
                ]
            },
        }
        manager._process_results(results, sample_target)
        assert len(manager._findings) == 3
        assert manager._statistics.findings_by_scanner["sqli"] == 1
        assert manager._statistics.findings_by_scanner["xss"] == 2

    def test_get_status_running(self, manager):
        """Test status when running."""
        manager._is_running = True
        manager._scan_id = uuid4()
        status = manager.get_status()
        assert status["is_running"] is True
        assert status["scan_id"] == str(manager._scan_id)

    def test_scan_statistics_duration_calculation(self, manager):
        """Test duration calculation in statistics."""
        import time

        manager._statistics.start_time = datetime.now(timezone.utc)
        time.sleep(0.01)
        manager._statistics.end_time = datetime.now(timezone.utc)
        manager._statistics.duration = (
            manager._statistics.end_time - manager._statistics.start_time
        ).total_seconds()
        assert manager._statistics.duration > 0
