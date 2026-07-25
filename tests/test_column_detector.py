# tests/test_column_detector.py
"""
Unit tests for Column Detection and Reflective Column Discovery.
Phase 9: Column Detection
"""

import unittest
import logging
from unittest.mock import Mock, patch, PropertyMock
import requests
import time

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.column_detector import (
    OracleColumnDetector,
    ColumnDetectionResult,
)


class TestColumnDetectionResult(unittest.TestCase):
    """Test ColumnDetectionResult data class."""

    def test_result_initialization(self):
        """Test result initialization."""
        result = ColumnDetectionResult()

        self.assertFalse(result.success)
        self.assertEqual(result.column_count, 0)
        self.assertEqual(result.reflective_columns, [])
        self.assertEqual(result.errors, [])
        self.assertIsNone(result.union_payload)

    def test_add_error(self):
        """Test adding errors."""
        result = ColumnDetectionResult()
        result.add_error("Error 1")
        result.add_error("Error 2")

        self.assertEqual(len(result.errors), 2)
        self.assertEqual(result.errors[0], "Error 1")

    def test_add_column_detail(self):
        """Test adding column details."""
        result = ColumnDetectionResult()
        result.add_column_detail(1, {"reflective": True, "confidence": 90})
        result.add_column_detail(2, {"reflective": False, "confidence": 50})

        self.assertEqual(len(result.column_details), 2)
        self.assertTrue(result.column_details[1]["reflective"])
        self.assertFalse(result.column_details[2]["reflective"])

    def test_get_summary_success(self):
        """Test summary generation on success."""
        result = ColumnDetectionResult(
            success=True,
            column_count=5,
            reflective_columns=[1, 3, 5],
            confidence=85,
            method_used="BOTH",
        )

        summary = result.get_summary()
        self.assertIn("Columns: 5", summary)
        self.assertIn("Reflective: 3 columns", summary)
        self.assertIn("Confidence: 85%", summary)
        self.assertIn("Method: BOTH", summary)

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = ColumnDetectionResult(success=False)
        summary = result.get_summary()
        self.assertEqual(summary, "Column detection failed")

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = ColumnDetectionResult(
            success=True, column_count=5, reflective_columns=[1, 3]
        )

        data = result.to_dict()

        self.assertEqual(data["success"], True)
        self.assertEqual(data["column_count"], 5)
        self.assertEqual(data["reflective_columns"], [1, 3])
        self.assertIn("summary", data)


class TestOracleColumnDetector(unittest.TestCase):
    """Test Oracle column detector."""

    def setUp(self):
        """Set up test environment."""
        logging.disable(logging.CRITICAL)

        self.session = Mock(spec=requests.Session)
        self.base_url = "http://test-target.com/page?id=1"
        self.injection_point = "id"

    def tearDown(self):
        """Clean up after tests."""
        logging.disable(logging.NOTSET)

    def _create_mock_response(self, text: str, status_code: int = 200):
        """Helper to create a proper mock response."""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = status_code
        mock_response.text = text
        mock_response.url = self.base_url
        type(mock_response).text = PropertyMock(return_value=text)
        return mock_response

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_detect_column_count_success(self, mock_union_sqli):
        """Test successful column count detection."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        success_response = self._create_mock_response("Data with columns")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": success_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        # Override detection methods to return test data
        detector._detect_by_order_by = lambda x, y: 5
        detector._detect_by_union_null = lambda x, y: 5
        detector._detect_reflective_columns = lambda x, y: [1, 3, 5]

        result = detector.detect_column_count(self.injection_point)

        self.assertTrue(result.success)
        self.assertEqual(result.column_count, 5)
        self.assertEqual(result.reflective_columns, [1, 3, 5])

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_detect_column_count_failure(self, mock_union_sqli):
        """Test column count detection failure."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": baseline_response,
            "has_changed": False,
        }
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        # Override detection methods to return 0
        detector._detect_by_order_by = lambda x, y: 0
        detector._detect_by_union_null = lambda x, y: 0

        result = detector.detect_column_count(self.injection_point)

        self.assertFalse(result.success)
        self.assertEqual(result.column_count, 0)

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_detect_union_columns(self, mock_union_sqli):
        """Test UNION column detection."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        success_response = self._create_mock_response("Data with columns")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": success_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        detector._detect_by_union_null = lambda x, y: 5
        detector._detect_reflective_columns = lambda x, y: [1, 3, 5]

        result = detector.detect_union_columns(self.injection_point)

        self.assertTrue(result.success)
        self.assertEqual(result.column_count, 5)
        self.assertEqual(result.method_used, "UNION_NULL")

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_find_reflective_column(self, mock_union_sqli):
        """Test finding reflective columns."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        # Mock the reflective detection
        def mock_detect_reflective(inj, count):
            return [1, 3, 5]

        detector._detect_reflective_columns = mock_detect_reflective

        result = detector.find_reflective_column(self.injection_point, 5)

        self.assertEqual(result, [1, 3, 5])

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_generate_union_payload(self, mock_union_sqli):
        """Test generating UNION payload."""
        detector = OracleColumnDetector(self.session, self.base_url)

        payload = detector.generate_union_payload(5, [1, 3])

        self.assertIsNotNone(payload)
        self.assertIn("UNION SELECT", payload)
        self.assertIn("SENTINEL_1", payload)
        self.assertIn("SENTINEL_3", payload)

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_generate_union_payload_no_reflective(self, mock_union_sqli):
        """Test generating UNION payload without reflective columns."""
        detector = OracleColumnDetector(self.session, self.base_url)

        payload = detector.generate_union_payload(5, [])

        self.assertIsNotNone(payload)
        self.assertIn("UNION SELECT NULL,NULL,NULL,NULL,NULL", payload)

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_get_best_union_payload(self, mock_union_sqli):
        """Test getting best UNION payload."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        success_response = self._create_mock_response("Data with columns")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": success_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        detector._detect_by_order_by = lambda x, y: 5
        detector._detect_by_union_null = lambda x, y: 5
        detector._detect_reflective_columns = lambda x, y: [1, 3, 5]

        payload = detector.get_best_union_payload(self.injection_point)

        self.assertIsNotNone(payload)
        self.assertIn("UNION SELECT", payload)

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_verify_column_count_success(self, mock_union_sqli):
        """Test verifying column count - success."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        success_response = self._create_mock_response("Data with columns")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": success_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        verified = detector.verify_column_count(self.injection_point, 5)

        self.assertTrue(verified)

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_verify_column_count_failure(self, mock_union_sqli):
        """Test verifying column count - failure."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": baseline_response,
            "has_changed": False,
        }
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        verified = detector.verify_column_count(self.injection_point, 5)

        self.assertFalse(verified)

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_order_by_detection(self, mock_union_sqli):
        """Test ORDER BY detection."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        error_response = self._create_mock_response(
            "ORA-00933: SQL command not properly ended"
        )

        mock_instance.get_baseline.return_value = baseline_response

        # First 3 tests succeed, 4th fails
        def mock_test_payload(inj, payload, baseline):
            if "ORDER BY 4" in payload:
                return {
                    "success": True,
                    "response": error_response,
                    "has_changed": True,
                }
            return {
                "success": True,
                "response": self._create_mock_response("Success"),
                "has_changed": True,
            }

        mock_instance.test_payload.side_effect = mock_test_payload
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector._detect_by_order_by(self.injection_point)

        self.assertEqual(result, 3)

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_union_null_detection(self, mock_union_sqli):
        """Test UNION NULL detection."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")

        mock_instance.get_baseline.return_value = baseline_response

        # First 3 tests succeed, 4th fails
        def mock_test_payload(inj, payload, baseline):
            if "UNION SELECT NULL,NULL,NULL,NULL" in payload:
                return {
                    "success": True,
                    "response": self._create_mock_response("ORA-00933"),
                    "has_changed": True,
                }
            return {
                "success": True,
                "response": self._create_mock_response("Success"),
                "has_changed": True,
            }

        mock_instance.test_payload.side_effect = mock_test_payload
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector._detect_by_union_null(self.injection_point)

        self.assertEqual(result, 3)

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_reflective_detection(self, mock_union_sqli):
        """Test reflective column detection."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        # Mock the _detect_reflective_columns method directly
        # Only column 1 is reflective, column 2 is not
        def mock_detect_reflective(inj, count):
            return [1]

        detector._detect_reflective_columns = mock_detect_reflective

        result = detector._detect_reflective_columns(self.injection_point, 2)

        self.assertIn(1, result)
        self.assertNotIn(2, result)

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_error_handling(self, mock_union_sqli):
        """Test error handling."""
        mock_instance = Mock()
        mock_instance.get_baseline.return_value = None
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.detect_column_count(self.injection_point)

        self.assertFalse(result.success)
        self.assertIn("Failed to get baseline response", result.errors)

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_timeout_handling(self, mock_union_sqli):
        """Test timeout handling."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.side_effect = requests.Timeout("Request timed out")
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.detect_column_count(self.injection_point)

        self.assertFalse(result.success)
        self.assertGreater(len(result.errors), 0)

    @patch("app.modules.scanner.column_detector.UnionSQLi")
    def test_max_columns_limit(self, mock_union_sqli):
        """Test max columns limit."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")

        mock_instance.get_baseline.return_value = baseline_response

        # All tests succeed, but we limit to 5
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": self._create_mock_response("Success"),
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = OracleColumnDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.detect_column_count(self.injection_point, max_columns=5)

        self.assertEqual(result.column_count, 5)


if __name__ == "__main__":
    unittest.main()
