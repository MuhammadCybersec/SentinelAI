# tests/test_datatype_detector.py
"""
Unit tests for Data Type Detection.
Phase 10: Data Type Detection
"""

import unittest
import logging
from unittest.mock import Mock, patch, PropertyMock
import requests

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.datatype_detector import (
    OracleDataTypeDetector,
    DataTypeDetectionResult,
)


class TestDataTypeDetectionResult(unittest.TestCase):
    """Test DataTypeDetectionResult data class."""

    def test_result_initialization(self):
        """Test result initialization."""
        result = DataTypeDetectionResult()

        self.assertFalse(result.success)
        self.assertEqual(result.column_count, 0)
        self.assertEqual(result.column_types, {})
        self.assertEqual(result.reflective_columns, [])
        self.assertEqual(result.errors, [])
        self.assertIsNone(result.working_union_payload)

    def test_add_error(self):
        """Test adding errors."""
        result = DataTypeDetectionResult()
        result.add_error("Error 1")
        result.add_error("Error 2")

        self.assertEqual(len(result.errors), 2)
        self.assertEqual(result.errors[0], "Error 1")

    def test_set_column_type(self):
        """Test setting column type."""
        result = DataTypeDetectionResult()
        result.set_column_type(1, "VARCHAR2")
        result.set_column_type(2, "NUMBER")

        self.assertEqual(result.get_column_type(1), "VARCHAR2")
        self.assertEqual(result.get_column_type(2), "NUMBER")
        self.assertEqual(result.get_column_type(3), None)

    def test_get_summary_success(self):
        """Test summary generation on success."""
        result = DataTypeDetectionResult(
            success=True,
            column_count=3,
            reflective_columns=[1, 3],
            best_reflective_column=1,
            confidence=85,
        )
        result.set_column_type(1, "VARCHAR2")
        result.set_column_type(2, "NUMBER")
        result.set_column_type(3, "VARCHAR2")

        summary = result.get_summary()
        self.assertIn("Columns: 3", summary)
        self.assertIn("Types: VARCHAR2: 2, NUMBER: 1", summary)
        self.assertIn("Reflective: 2 columns", summary)
        self.assertIn("Best reflective: column 1", summary)
        self.assertIn("Confidence: 85%", summary)

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = DataTypeDetectionResult(success=False)
        summary = result.get_summary()
        self.assertEqual(summary, "Data type detection failed")

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = DataTypeDetectionResult(success=True, column_count=2, confidence=80)
        result.set_column_type(1, "VARCHAR2")
        result.set_column_type(2, "NUMBER")

        data = result.to_dict()

        self.assertEqual(data["success"], True)
        self.assertEqual(data["column_count"], 2)
        self.assertEqual(data["column_types"][1], "VARCHAR2")
        self.assertEqual(data["column_types"][2], "NUMBER")
        self.assertEqual(data["confidence"], 80)
        self.assertIn("summary", data)


class TestOracleDataTypeDetector(unittest.TestCase):
    """Test Oracle data type detector."""

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

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_detect_column_types_success(self, mock_union_sqli):
        """Test successful column type detection."""
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

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance
        detector.column_count = 3
        detector.reflective_columns = [1, 3]

        # Override detection methods
        detector._detect_column_type = lambda x, y, z, w: ("VARCHAR2", 90)
        detector._detect_reflective_columns = lambda x, y, z: [1, 3]

        result = detector.detect_column_types(self.injection_point, 3)

        self.assertTrue(result.success)
        self.assertEqual(result.column_count, 3)
        self.assertEqual(result.reflective_columns, [1, 3])

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_detect_column_types_failure(self, mock_union_sqli):
        """Test column type detection failure."""
        mock_instance = Mock()
        mock_instance.get_baseline.return_value = None
        mock_union_sqli.return_value = mock_instance

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.detect_column_types(self.injection_point)

        self.assertFalse(result.success)
        self.assertIn("Failed to get baseline response", result.errors)

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_detect_string_columns(self, mock_union_sqli):
        """Test detecting string columns."""
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

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        string_cols = detector.detect_string_columns(self.injection_point, 3)

        self.assertGreater(len(string_cols), 0)

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_detect_numeric_columns(self, mock_union_sqli):
        """Test detecting numeric columns."""
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

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        num_cols = detector.detect_numeric_columns(self.injection_point, 3)

        self.assertGreater(len(num_cols), 0)

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_detect_date_columns(self, mock_union_sqli):
        """Test detecting date columns."""
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

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        date_cols = detector.detect_date_columns(self.injection_point, 3)

        self.assertGreater(len(date_cols), 0)

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_detect_null_columns(self, mock_union_sqli):
        """Test detecting NULL columns."""
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

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        null_cols = detector.detect_null_columns(self.injection_point, 3)

        self.assertGreater(len(null_cols), 0)

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_detect_reflective_columns(self, mock_union_sqli):
        """Test detecting reflective columns."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        reflective_response = self._create_mock_response("Data with REFL_1")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": reflective_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        reflective = detector.detect_reflective_columns(self.injection_point, 3)

        self.assertGreater(len(reflective), 0)

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_build_union_payload(self, mock_union_sqli):
        """Test building UNION payload."""
        detector = OracleDataTypeDetector(self.session, self.base_url)

        payload = detector.build_union_payload(3, 1, "TEST")

        self.assertIn("UNION SELECT", payload)
        self.assertIn("'TEST'", payload)

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_verify_payload_success(self, mock_union_sqli):
        """Test payload verification - success."""
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

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        verified = detector.verify_payload(
            self.injection_point, "UNION SELECT 1,2 FROM dual--"
        )

        self.assertTrue(verified)

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_verify_payload_failure(self, mock_union_sqli):
        """Test payload verification - failure."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        error_response = self._create_mock_response("ORA-00933: error")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": error_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        verified = detector.verify_payload(
            self.injection_point, "UNION SELECT 1,2 FROM dual--"
        )

        self.assertFalse(verified)

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
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

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        # Set up result
        result = DataTypeDetectionResult(
            success=True,
            column_count=3,
            reflective_columns=[1, 3],
            working_union_payload="'UNION SELECT 'TEST',NULL,NULL FROM dual--",
        )
        detector.datatype_result = result

        payload = detector.get_best_union_payload(self.injection_point)

        self.assertIsNotNone(payload)
        self.assertIn("UNION SELECT", payload)

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_get_reflective_column(self, mock_union_sqli):
        """Test getting reflective column."""
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

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        # Set up result
        result = DataTypeDetectionResult(
            success=True,
            column_count=3,
            reflective_columns=[1, 3],
            best_reflective_column=1,
        )
        detector.datatype_result = result

        reflective = detector.get_reflective_column(self.injection_point)

        self.assertEqual(reflective, 1)

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_error_handling(self, mock_union_sqli):
        """Test error handling."""
        mock_instance = Mock()
        mock_instance.get_baseline.side_effect = Exception("Connection error")
        mock_union_sqli.return_value = mock_instance

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.detect_column_types(self.injection_point)

        self.assertFalse(result.success)
        self.assertGreater(len(result.errors), 0)

    @patch("app.modules.scanner.datatype_detector.UnionSQLi")
    def test_column_type_detection_priority(self, mock_union_sqli):
        """Test column type detection priority."""
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

        detector = OracleDataTypeDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        dtype, confidence = detector._detect_column_type(
            self.injection_point, 1, 3, baseline_response
        )

        self.assertIn(dtype, ["VARCHAR2", "NUMBER", "DATE", "LOB", "NULL", "UNKNOWN"])


if __name__ == "__main__":
    unittest.main()
