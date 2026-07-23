"""
Automated tests for Error-Based SQL Injection engine.
"""

import unittest
from unittest.mock import Mock, patch

from app.modules.scanner.modules.error_payloads import ErrorPayloadGenerator
from app.modules.scanner.modules.error_detector import ErrorDetector
from app.modules.scanner.modules.error_extractor import ErrorExtractor
from app.modules.scanner.modules.error_sqli import ErrorSQLiScanner, SQLInjectionManager


class TestErrorPayloads(unittest.TestCase):
    """Test ErrorPayloadGenerator."""

    def setUp(self):
        self.generator = ErrorPayloadGenerator()

    def test_get_single_quote_payload(self):
        """Test single quote payload."""
        payload = self.generator.get_single_quote_payload()
        self.assertEqual(payload, "'")

    def test_get_database_payload(self):
        """Test database extraction payload."""
        payload = self.generator.get_database_payload()
        self.assertIn("DATABASE", payload)

    def test_dbms_specific_payloads(self):
        """Test DBMS-specific payloads."""
        for dbms in ["MySQL", "PostgreSQL", "MSSQL", "Oracle"]:
            gen = ErrorPayloadGenerator(dbms)
            self.assertIsNotNone(gen.get_database_payload())
            self.assertIsNotNone(gen.get_version_payload())


class TestErrorDetector(unittest.TestCase):
    """Test ErrorDetector."""

    def test_dbms_signatures(self):
        """Test DBMS error signatures."""
        detector = ErrorDetector("http://example.com")

        # MySQL signature
        body = "You have an error in your SQL syntax"
        self.assertEqual(detector._detect_dbms(body), "MySQL")

        # PostgreSQL signature
        body = "ERROR: syntax error at or near"
        self.assertEqual(detector._detect_dbms(body), "PostgreSQL")

        # MSSQL signature
        body = "Unclosed quotation mark"
        self.assertEqual(detector._detect_dbms(body), "MSSQL")

        # Oracle signature
        body = "ORA-00933: SQL command not properly ended"
        self.assertEqual(detector._detect_dbms(body), "Oracle")

    def test_has_sql_error(self):
        """Test SQL error detection."""
        detector = ErrorDetector("http://example.com")

        body = "SQL syntax error"
        self.assertTrue(detector._has_sql_error(body))

        body = "Normal content"
        self.assertFalse(detector._has_sql_error(body))

        body = "MySQL error: syntax error"
        self.assertTrue(detector._has_sql_error(body))


class TestErrorExtractor(unittest.TestCase):
    """Test ErrorExtractor."""

    @patch(
        "app.modules.scanner.modules.error_extractor.ErrorExtractor._extract_from_error"
    )
    def test_extract_database(self, mock_extract):
        """Test database extraction."""
        extractor = ErrorExtractor("http://example.com")
        mock_extract.return_value = "test_db"

        result = extractor.extract_database()
        self.assertEqual(result, "test_db")

    @patch(
        "app.modules.scanner.modules.error_extractor.ErrorExtractor._extract_from_error"
    )
    def test_extract_version(self, mock_extract):
        """Test version extraction."""
        extractor = ErrorExtractor("http://example.com")
        mock_extract.return_value = "8.0.31"

        result = extractor.extract_version()
        self.assertEqual(result, "8.0.31")

    @patch(
        "app.modules.scanner.modules.error_extractor.ErrorExtractor._extract_from_error"
    )
    def test_extract_tables(self, mock_extract):
        """Test table extraction."""
        extractor = ErrorExtractor("http://example.com")
        mock_extract.side_effect = ["users", "products", None]

        tables = extractor.extract_tables(limit=3)
        self.assertEqual(tables, ["users", "products"])
        self.assertEqual(len(tables), 2)


class TestErrorSQLiScanner(unittest.TestCase):
    """Test ErrorSQLiScanner."""

    @patch("app.modules.scanner.modules.error_sqli.ErrorDetector")
    @patch("app.modules.scanner.modules.error_sqli.ErrorExtractor")
    def test_scan(self, MockExtractor, MockDetector):
        """Test scanner scan method."""
        # Setup mocks
        mock_detector = Mock()
        mock_detector.detect.return_value = (True, "MySQL")
        MockDetector.return_value = mock_detector

        mock_extractor = Mock()
        mock_extractor.extract_database.return_value = "test_db"
        mock_extractor.extract_version.return_value = "8.0.31"
        mock_extractor.extract_user.return_value = "root"
        mock_extractor.extract_tables.return_value = ["users", "products"]
        mock_extractor.extract_columns.return_value = ["username", "password"]
        MockExtractor.return_value = mock_extractor

        scanner = ErrorSQLiScanner("http://example.com")
        findings = scanner.scan()

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].vulnerable)
        self.assertEqual(findings[0].dbms, "MySQL")


class TestSQLiManagerIntegration(unittest.TestCase):
    """Test SQLiManager integration with Error-Based SQLi."""

    @patch("app.modules.scanner.modules.error_sqli.UnionSQLiScanner")
    @patch("app.modules.scanner.modules.error_sqli.ErrorSQLiScanner")
    def test_fallback_to_error(self, MockError, MockUnion):
        """Test that manager falls back to Error-Based when UNION fails."""
        # Union scanner returns no findings
        mock_union = Mock()
        mock_union.scan.return_value = []

        # Error scanner returns findings
        mock_error = Mock()
        mock_error.scan.return_value = [Mock()]

        MockUnion.return_value = mock_union
        MockError.return_value = mock_error

        manager = SQLInjectionManager("http://example.com")
        manager.union_scanner = mock_union
        manager.error_scanner = mock_error

        result = manager.scan()
        self.assertEqual(result["type"], "error")


if __name__ == "__main__":
    unittest.main()
