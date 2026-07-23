# tests/test_oracle_enum_phase1.py

"""
Unit tests for Phase 1: Oracle Detection.
"""

import unittest
import logging
import requests
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.dbms.oracle import OracleEnum


class TestOracleEnumPhase1(unittest.TestCase):
    """Test suite for Phase 1: Oracle Detection."""

    def setUp(self):
        """Set up test environment."""
        # Disable logging during tests
        logging.disable(logging.CRITICAL)

        # Create mock session
        self.session = Mock(spec=requests.Session)
        self.base_url = "http://test-target.com"
        self.injection_point = "id"

        # Initialize OracleEnum with mocks
        self.oracle_enum = OracleEnum(self.session, self.base_url)

    def tearDown(self):
        """Clean up after tests."""
        logging.disable(logging.NOTSET)

    @patch("app.modules.scanner.dbms.oracle.oracle_enum.UnionSQLi")
    def test_detect_oracle_success(self, mock_union_sqli):
        """Test successful Oracle detection."""
        # Mock UnionSQLi instance
        mock_instance = Mock()
        mock_instance.detect_dbms.return_value = "Oracle"
        mock_union_sqli.return_value = mock_instance

        # Test detection
        result = self.oracle_enum.detect_oracle(self.injection_point)

        # Assertions
        self.assertTrue(result)
        self.assertEqual(self.oracle_enum.dbms_type, "Oracle")

        # Verify UnionSQLi was called correctly
        mock_union_sqli.assert_called_once_with(
            self.oracle_enum.session, self.oracle_enum.base_url, self.oracle_enum.logger
        )
        mock_instance.detect_dbms.assert_called_once_with(self.injection_point)

    @patch("app.modules.scanner.dbms.oracle.oracle_enum.UnionSQLi")
    def test_detect_oracle_failure_not_oracle(self, mock_union_sqli):
        """Test detection failure when DBMS is not Oracle."""
        # Mock UnionSQLi instance
        mock_instance = Mock()
        mock_instance.detect_dbms.return_value = "MySQL"
        mock_union_sqli.return_value = mock_instance

        # Test detection
        result = self.oracle_enum.detect_oracle(self.injection_point)

        # Assertions
        self.assertFalse(result)
        self.assertEqual(self.oracle_enum.dbms_type, "MySQL")

    @patch("app.modules.scanner.dbms.oracle.oracle_enum.UnionSQLi")
    def test_detect_oracle_error_handling(self, mock_union_sqli):
        """Test error handling during detection."""
        # Mock UnionSQLi to raise exception
        mock_instance = Mock()
        mock_instance.detect_dbms.side_effect = Exception("Connection error")
        mock_union_sqli.return_value = mock_instance

        # Test detection
        result = self.oracle_enum.detect_oracle(self.injection_point)

        # Assertions
        self.assertFalse(result)
        self.assertIsNone(self.oracle_enum.dbms_type)

    @patch("app.modules.scanner.dbms.oracle.oracle_enum.UnionSQLi")
    def test_run_phase_1_wrapper(self, mock_union_sqli):
        """Test the Phase 1 wrapper method."""
        # Mock UnionSQLi instance
        mock_instance = Mock()
        mock_instance.detect_dbms.return_value = "Oracle"
        mock_union_sqli.return_value = mock_instance

        # Test run_phase_1
        result = self.oracle_enum.run_phase_1(self.injection_point)

        # Assertions
        self.assertTrue(result)
        self.assertEqual(self.oracle_enum.dbms_type, "Oracle")


class TestOracleScorer(unittest.TestCase):
    """Test Oracle scorer functionality."""

    def setUp(self):
        """Set up test environment."""
        from app.modules.scanner.dbms.oracle.scorer import OracleScorer

        self.scorer = OracleScorer()

    def test_score_table(self):
        """Test table scoring."""
        # High priority tables
        self.assertEqual(self.scorer.score_table("USERS"), 100)
        self.assertEqual(self.scorer.score_table("ACCOUNTS"), 90)
        self.assertEqual(self.scorer.score_table("EMPLOYEES"), 50)

        # Partial matches
        self.assertGreater(self.scorer.score_table("USER_TABLE"), 0)
        self.assertGreater(self.scorer.score_table("ACCOUNT_INFO"), 0)

        # Low priority
        self.assertEqual(self.scorer.score_table("DUAL"), 5)
        self.assertEqual(self.scorer.score_table("RANDOM_TABLE"), 0)

    def test_find_best_table(self):
        """Test finding best table from list."""
        tables = ["DUAL", "USERS", "EMPLOYEES", "RANDOM"]
        best = self.scorer.find_best_table(tables)
        self.assertEqual(best, "USERS")

        # Empty list
        self.assertIsNone(self.scorer.find_best_table([]))

        # Only low priority
        tables = ["DUAL", "TAB"]
        best = self.scorer.find_best_table(tables)
        self.assertEqual(best, "DUAL")

    def test_score_username_column(self):
        """Test username column scoring."""
        self.assertEqual(self.scorer.score_username_column("USERNAME"), 100)
        self.assertEqual(self.scorer.score_username_column("USER"), 95)
        self.assertEqual(self.scorer.score_username_column("EMAIL"), 80)
        self.assertGreater(self.scorer.score_username_column("USER_ID"), 0)

        # No match
        self.assertEqual(self.scorer.score_username_column("RANDOM"), 0)

    def test_score_password_column(self):
        """Test password column scoring."""
        self.assertEqual(self.scorer.score_password_column("PASSWORD"), 100)
        self.assertEqual(self.scorer.score_password_column("PASS"), 95)
        self.assertEqual(self.scorer.score_password_column("HASH"), 85)
        self.assertGreater(self.scorer.score_password_column("PASS_HASH"), 0)

        # No match
        self.assertEqual(self.scorer.score_password_column("RANDOM"), 0)

    def test_find_administrator(self):
        """Test administrator detection."""
        credentials = [
            {"username": "admin", "password": "pass1"},
            {"username": "user", "password": "pass2"},
            {"username": "administrator", "password": "pass3"},
        ]
        admin = self.scorer.find_administrator(credentials)
        self.assertEqual(admin["username"], "administrator")

        # No admin
        credentials = [{"username": "user1", "password": "pass"}]
        self.assertIsNone(self.scorer.find_administrator(credentials))


if __name__ == "__main__":
    unittest.main()
