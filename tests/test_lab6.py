"""
Unit tests for PortSwigger Lab 6 handler.
"""

import unittest
from unittest.mock import Mock, patch

from app.modules.scanner.modules.lab6_handler import Lab6Handler, solve_lab6
from app.modules.scanner.modules.union_sqli import UnionFinding


class TestLab6Handler(unittest.TestCase):
    """Test Lab 6 handler."""

    def setUp(self):
        self.target = "https://0aXX.web-security-academy.net/filter?category=Gifts"
        self.handler = Lab6Handler(self.target)

    def test_parameter_detection(self):
        """Test parameter detection from URL."""
        test_cases = [
            ("https://example.com/filter?category=Gifts", "category"),
            ("https://example.com/product?productId=1", "productId"),
            ("https://example.com/page?id=1", "id"),
            ("https://example.com/data?filter=all", "filter"),
        ]

        for url, expected in test_cases:
            handler = Lab6Handler(url)
            self.assertEqual(handler.parameter, expected)

    def test_extract_credentials_from_findings(self):
        """Test credential extraction from UNION findings."""
        # Create mock findings
        finding = UnionFinding(
            vulnerable=True,
            url="https://example.com",
            parameter="category",
            payload="' UNION SELECT username, password FROM users--",
            technique="UNION-Based",
            dbms="MySQL",
            column_count=2,
            visible_columns=[0, 1],
            extracted_data=[
                {"username": "administrator", "password": "password123"},
                {"username": "carlos", "password": "carlos123"},
            ],
        )

        credentials = self.handler._extract_credentials_from_findings([finding])
        self.assertEqual(len(credentials), 2)
        self.assertEqual(credentials[0]["username"], "administrator")
        self.assertEqual(credentials[0]["password"], "password123")

    def test_extract_credentials_from_error_findings(self):
        """Test credential extraction from Error findings."""
        from app.modules.scanner.modules.error_sqli import ErrorFinding

        finding = ErrorFinding(
            vulnerable=True,
            url="https://example.com",
            parameter="category",
            technique="Error-Based",
            dbms="MySQL",
            credentials=[
                {"username": "administrator", "password": "password123"},
            ],
        )

        credentials = self.handler._extract_credentials_from_error_findings([finding])
        self.assertEqual(len(credentials), 1)
        self.assertEqual(credentials[0]["username"], "administrator")

    @patch("app.modules.scanner.modules.lab6_handler.UnionSQLiScanner")
    def test_run_with_union_success(self, MockUnion):
        """Test run with successful UNION detection."""
        # Setup mock union scanner
        mock_finding = UnionFinding(
            vulnerable=True,
            url=self.target,
            parameter="category",
            payload="' UNION SELECT username, password FROM users--",
            technique="UNION-Based",
            dbms="MySQL",
            column_count=2,
            visible_columns=[0, 1],
            extracted_data=[{"username": "administrator", "password": "password123"}],
        )

        mock_scanner = Mock()
        mock_scanner.scan.return_value = [mock_finding]
        MockUnion.return_value = mock_scanner

        # Patch post exploitation
        with patch(
            "app.agents.post_exploitation_agent.PostExploitationAgent"
        ) as MockPostAgent:
            mock_post = Mock()
            mock_post.exploit_credentials.return_value = True
            MockPostAgent.return_value = mock_post

            result = self.handler.run()

            self.assertTrue(result["lab_completed"])
            self.assertEqual(result["scan_type"], "union")
            self.assertEqual(len(result["credentials"]), 1)

    @patch("app.modules.scanner.modules.lab6_handler.UnionSQLiScanner")
    @patch("app.modules.scanner.modules.lab6_handler.ErrorSQLiScanner")
    def test_fallback_to_error(self, MockError, MockUnion):
        """Test fallback to Error-Based SQLi when UNION fails."""
        # Union returns empty
        mock_union = Mock()
        mock_union.scan.return_value = []
        MockUnion.return_value = mock_union

        # Error returns findings
        from app.modules.scanner.modules.error_sqli import ErrorFinding

        mock_error = Mock()
        mock_error.scan.return_value = [
            ErrorFinding(
                vulnerable=True,
                url=self.target,
                parameter="category",
                technique="Error-Based",
                dbms="MySQL",
                credentials=[{"username": "administrator", "password": "password123"}],
            )
        ]
        MockError.return_value = mock_error

        with patch(
            "app.agents.post_exploitation_agent.PostExploitationAgent"
        ) as MockPostAgent:
            mock_post = Mock()
            mock_post.exploit_credentials.return_value = True
            MockPostAgent.return_value = mock_post

            result = self.handler.run()
            self.assertTrue(result["lab_completed"])
            self.assertEqual(result["scan_type"], "error")


class TestSolveLab6(unittest.TestCase):
    """Test convenience function."""

    @patch("app.modules.scanner.modules.lab6_handler.Lab6Handler")
    def test_solve_lab6(self, MockHandler):
        """Test solve_lab6 convenience function."""
        mock_handler = Mock()
        mock_handler.run.return_value = {"lab_completed": True}
        MockHandler.return_value = mock_handler

        result = solve_lab6("https://example.com")
        self.assertTrue(result["lab_completed"])
        MockHandler.assert_called_once_with("https://example.com")


if __name__ == "__main__":
    unittest.main()
