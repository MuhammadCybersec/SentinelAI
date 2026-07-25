# tests/test_sqli_detector.py
"""
Unit tests for SQL Injection detection.
Phase 7: SQL Injection Detection
"""

import unittest
import logging
from unittest.mock import Mock, patch, PropertyMock
import requests
import time

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.sqli_detector import SQLiDetector, SQLiDetectionResult


class TestSQLiDetectionResult(unittest.TestCase):
    """Test SQLiDetectionResult data class."""

    def test_result_initialization(self):
        """Test result initialization."""
        result = SQLiDetectionResult()

        self.assertFalse(result.success)
        self.assertIsNone(result.parameter)
        self.assertIsNone(result.injection_type)
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.evidence, [])
        self.assertEqual(result.errors, [])

    def test_add_evidence(self):
        """Test adding evidence."""
        result = SQLiDetectionResult()
        result.add_evidence("Evidence 1")
        result.add_evidence("Evidence 2")
        result.add_evidence("Evidence 1")  # Duplicate

        self.assertEqual(len(result.evidence), 2)
        self.assertIn("Evidence 1", result.evidence)

    def test_add_error(self):
        """Test adding errors."""
        result = SQLiDetectionResult()
        result.add_error("Error 1")
        result.add_error("Error 2")

        self.assertEqual(len(result.errors), 2)

    def test_add_dbms_confidence(self):
        """Test adding DBMS confidence."""
        result = SQLiDetectionResult()
        result.add_dbms_confidence("oracle", 80)
        result.add_dbms_confidence("mysql", 20)

        self.assertEqual(result.dbms_confidence["oracle"], 80)
        self.assertEqual(result.dbms_confidence["mysql"], 20)

    def test_get_summary_success(self):
        """Test summary generation on success."""
        result = SQLiDetectionResult(
            success=True,
            parameter="id",
            injection_type="UNION",
            confidence=85,
            risk_level="HIGH",
            payload="' UNION SELECT NULL--",
            column_count=3,
        )
        result.add_evidence("Evidence 1")

        summary = result.get_summary()
        self.assertIn("Parameter: id", summary)
        self.assertIn("Type: UNION", summary)
        self.assertIn("Confidence: 85%", summary)
        self.assertIn("Risk: HIGH", summary)
        self.assertIn("Columns: 3", summary)

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = SQLiDetectionResult(success=False)
        summary = result.get_summary()
        self.assertEqual(summary, "SQL Injection not detected")

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = SQLiDetectionResult(success=True, parameter="id", confidence=75)
        result.add_evidence("Test evidence")

        data = result.to_dict()

        self.assertEqual(data["success"], True)
        self.assertEqual(data["parameter"], "id")
        self.assertEqual(data["confidence"], 75)
        self.assertIn("summary", data)


class TestSQLiDetector(unittest.TestCase):
    """Test SQL injection detector."""

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

    @patch("app.modules.scanner.sqli_detector.UnionSQLi")
    def test_detect_union_success(self, mock_union_sqli):
        """Test UNION injection detection."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        union_response = self._create_mock_response("UNION SELECT NULL FROM dual--")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": union_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = SQLiDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.detect_union(self.injection_point)

        self.assertTrue(result["success"])
        self.assertGreater(result["confidence"], 0)

    @patch("app.modules.scanner.sqli_detector.UnionSQLi")
    def test_detect_boolean_success(self, mock_union_sqli):
        """Test Boolean injection detection."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        true_response = self._create_mock_response("True response - different")
        false_response = self._create_mock_response("False response")

        mock_instance.get_baseline.return_value = baseline_response

        # Return true response first, then false
        mock_instance.test_payload.side_effect = [
            {"success": True, "response": true_response, "has_changed": True},
            {"success": True, "response": false_response, "has_changed": False},
            {"success": True, "response": true_response, "has_changed": True},
            {"success": True, "response": false_response, "has_changed": False},
            {"success": True, "response": true_response, "has_changed": True},
            {"success": True, "response": false_response, "has_changed": False},
        ]
        mock_union_sqli.return_value = mock_instance

        detector = SQLiDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.detect_boolean(self.injection_point)

        self.assertIsNotNone(result)

    @patch("app.modules.scanner.sqli_detector.UnionSQLi")
    def test_detect_error_based_success(self, mock_union_sqli):
        """Test Error-based injection detection."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        error_response = self._create_mock_response(
            "ORA-00933: SQL command not properly ended"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": error_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = SQLiDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.detect_error_based(self.injection_point)

        self.assertTrue(result["success"])
        self.assertGreater(result["confidence"], 50)

    @patch("app.modules.scanner.sqli_detector.UnionSQLi")
    def test_detect_time_based_success(self, mock_union_sqli):
        """Test Time-based injection detection."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        time_response = self._create_mock_response("Response after sleep")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": time_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = SQLiDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        # Mock the _send_payload_with_metrics method to return a delayed response
        def mock_send_payload(inj, payload, baseline):
            return {
                "success": True,
                "response": time_response,
                "response_text": "Response after sleep",
                "size": 100,
                "time": 5.5,  # Simulate 5.5 second delay
                "has_changed": True,
                "status_code": 200,
            }

        detector._send_payload_with_metrics = mock_send_payload

        # Mock time to avoid sleep
        with patch("time.sleep") as mock_sleep:
            mock_sleep.return_value = None

            # Need to mock time.time for the elapsed time calculation
            with patch("time.time") as mock_time:
                # _get_baseline: start_time (0), end_time (0.1) = 2 values
                # detect_time_based: start_time (0), end_time (5.5) = 2 values
                # Total: 4 values
                mock_time.side_effect = [0, 0.1, 0, 5.5]

                result = detector.detect_time_based(
                    self.injection_point, sleep_seconds=5
                )

        self.assertIsNotNone(result)

    @patch("app.modules.scanner.sqli_detector.UnionSQLi")
    def test_detect_column_count(self, mock_union_sqli):
        """Test column count detection."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        union_response = self._create_mock_response(
            "UNION SELECT NULL,NULL FROM dual--"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": union_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = SQLiDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        count = detector.detect_column_count(self.injection_point)
        self.assertEqual(count, 1)  # First successful union

    @patch("app.modules.scanner.sqli_detector.UnionSQLi")
    def test_verify_success(self, mock_union_sqli):
        """Test verification of injection."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        verified_response = self._create_mock_response("ORA-00933: error")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": verified_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = SQLiDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.verify(self.injection_point, "' AND 1=1--")

        self.assertTrue(result["verified"])
        self.assertGreater(result["confidence"], 0)

    @patch("app.modules.scanner.sqli_detector.UnionSQLi")
    def test_detect_full(self, mock_union_sqli):
        """Test full detection workflow."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        vuln_response = self._create_mock_response("Oracle Database 19c")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": vuln_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = SQLiDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.detect(self.injection_point)

        self.assertIsNotNone(result)

    @patch("app.modules.scanner.sqli_detector.UnionSQLi")
    def test_is_vulnerable(self, mock_union_sqli):
        """Test is_vulnerable convenience method."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        vuln_response = self._create_mock_response("Oracle Database 19c")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": vuln_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = SQLiDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        is_vuln = detector.is_vulnerable(self.injection_point)
        self.assertTrue(is_vuln)

    @patch("app.modules.scanner.sqli_detector.UnionSQLi")
    def test_get_confidence(self, mock_union_sqli):
        """Test get_confidence convenience method."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        vuln_response = self._create_mock_response("Oracle Database 19c")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": vuln_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = SQLiDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        confidence = detector.get_confidence(self.injection_point)
        self.assertGreater(confidence, 0)

    @patch("app.modules.scanner.sqli_detector.UnionSQLi")
    def test_no_injection(self, mock_union_sqli):
        """Test when no injection is found."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        normal_response = self._create_mock_response("Normal response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": normal_response,
            "has_changed": False,
        }
        mock_union_sqli.return_value = mock_instance

        detector = SQLiDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.detect(self.injection_point)

        self.assertFalse(result.success)
        self.assertEqual(result.confidence, 0)


if __name__ == "__main__":
    unittest.main()
