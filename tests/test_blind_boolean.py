# tests/test_blind_boolean.py
"""
Unit tests for Boolean-Based Blind SQL Injection Detection.
Phase 11: Boolean Blind Detection
"""

import logging
import os
import sys
import unittest
from unittest.mock import Mock, PropertyMock, patch

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.blind_boolean import (
    BlindBooleanResult,
    OracleBlindBooleanEngine,
)


class TestBlindBooleanResult(unittest.TestCase):
    """Test BlindBooleanResult data class."""

    def test_result_initialization(self):
        """Test result initialization."""
        result = BlindBooleanResult()

        self.assertFalse(result.success)
        self.assertFalse(result.is_vulnerable)
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.working_payloads, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.evidence, [])

    def test_add_error(self):
        """Test adding errors."""
        result = BlindBooleanResult()
        result.add_error("Error 1")
        result.add_error("Error 2")

        self.assertEqual(len(result.errors), 2)
        self.assertEqual(result.errors[0], "Error 1")

    def test_add_evidence(self):
        """Test adding evidence."""
        result = BlindBooleanResult()
        result.add_evidence("Evidence 1")
        result.add_evidence("Evidence 2")
        result.add_evidence("Evidence 1")  # Duplicate

        self.assertEqual(len(result.evidence), 2)
        self.assertIn("Evidence 1", result.evidence)

    def test_add_working_payload(self):
        """Test adding working payload."""
        result = BlindBooleanResult()
        result.add_working_payload("payload1")
        result.add_working_payload("payload2")
        result.add_working_payload("payload1")  # Duplicate

        self.assertEqual(len(result.working_payloads), 2)
        self.assertIn("payload1", result.working_payloads)

    def test_get_summary_success_vulnerable(self):
        """Test summary generation on vulnerable."""
        result = BlindBooleanResult(
            success=True,
            is_vulnerable=True,
            confidence=90,
            comparison_method="LENGTH",
            best_true_payload="'AND 1=1--",
        )

        summary = result.get_summary()
        self.assertIn("Vulnerable: YES", summary)
        self.assertIn("Method: LENGTH", summary)
        self.assertIn("Confidence: 90%", summary)

    def test_get_summary_success_not_vulnerable(self):
        """Test summary generation on not vulnerable."""
        result = BlindBooleanResult(success=True, is_vulnerable=False)

        summary = result.get_summary()
        self.assertEqual(summary, "Boolean blind SQL injection not detected")

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = BlindBooleanResult(success=False)
        summary = result.get_summary()
        self.assertEqual(summary, "Boolean blind detection failed")

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = BlindBooleanResult(
            success=True,
            is_vulnerable=True,
            confidence=85,
            true_response_length=1000,
            false_response_length=500,
        )
        result.add_evidence("Test evidence")

        data = result.to_dict()

        self.assertEqual(data["success"], True)
        self.assertEqual(data["is_vulnerable"], True)
        self.assertEqual(data["confidence"], 85)
        self.assertEqual(data["true_response_length"], 1000)
        self.assertEqual(data["false_response_length"], 500)
        self.assertIn("summary", data)


class TestOracleBlindBooleanEngine(unittest.TestCase):
    """Test Oracle Blind Boolean Engine."""

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

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_detect_boolean_blind_vulnerable_length(self, mock_union_sqli):
        """Test detecting boolean blind - vulnerable (length difference)."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        true_response = self._create_mock_response("True response with extra content")
        false_response = self._create_mock_response("False response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": true_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        # Patch the send_payload to return different responses
        def mock_send(inj, payload):
            if "1=1" in payload or "'A'='A'" in payload:
                return true_response
            return false_response

        engine = OracleBlindBooleanEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance
        engine._send_payload = mock_send

        result = engine.detect_boolean_blind(self.injection_point)

        self.assertTrue(result.success)
        self.assertTrue(result.is_vulnerable)
        self.assertEqual(result.comparison_method, "LENGTH")
        self.assertGreater(result.confidence, 50)

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_detect_boolean_blind_not_vulnerable(self, mock_union_sqli):
        """Test detecting boolean blind - not vulnerable."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        same_response = self._create_mock_response("Same response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": same_response,
            "has_changed": False,
        }
        mock_union_sqli.return_value = mock_instance

        # Patch the send_payload to return same response
        def mock_send(inj, payload):
            return same_response

        engine = OracleBlindBooleanEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance
        engine._send_payload = mock_send

        result = engine.detect_boolean_blind(self.injection_point)

        self.assertTrue(result.success)
        self.assertFalse(result.is_vulnerable)

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_detect_boolean_blind_content_difference(self, mock_union_sqli):
        """Test detecting boolean blind - content difference."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        true_response = self._create_mock_response(
            "True response with different content"
        )
        false_response = self._create_mock_response(
            "Different content in false response"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": true_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        # Patch the send_payload to return different responses
        def mock_send(inj, payload):
            if "1=1" in payload or "'A'='A'" in payload:
                return true_response
            return false_response

        engine = OracleBlindBooleanEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance
        engine._send_payload = mock_send

        # Make the true and false responses different in content
        engine._detect_length_difference = lambda x, y: False  # No length diff
        engine._detect_content_difference = lambda x, y: True  # Content diff

        result = engine.detect_boolean_blind(self.injection_point)

        self.assertTrue(result.success)
        self.assertTrue(result.is_vulnerable)
        self.assertEqual(result.comparison_method, "CONTENT")

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_compare_true_false(self, mock_union_sqli):
        """Test comparing true/false conditions."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline response")
        true_response = self._create_mock_response("True response")
        false_response = self._create_mock_response("False response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": true_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        engine = OracleBlindBooleanEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance
        engine._send_payload = lambda inj, p: (
            true_response if "1=1" in p else false_response
        )

        result = engine.compare_true_false(
            self.injection_point, "AND 1=1--", "AND 1=2--"
        )

        self.assertTrue(result["success"])
        self.assertTrue(result["is_vulnerable"])

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_calculate_similarity(self, mock_union_sqli):
        """Test calculating similarity."""
        engine = OracleBlindBooleanEngine(self.session, self.base_url)

        text1 = "This is a test response with some content"
        text2 = "This is a different response with other content"

        similarity = engine.calculate_similarity(text1, text2)

        self.assertGreaterEqual(similarity, 0)
        self.assertLessEqual(similarity, 1)

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_build_boolean_payloads(self, mock_union_sqli):
        """Test building boolean payloads."""
        engine = OracleBlindBooleanEngine(self.session, self.base_url)

        payloads = engine.build_boolean_payloads("1=1", "AND")

        self.assertGreater(len(payloads), 0)
        self.assertTrue(any("1=1" in p for p in payloads))

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_find_best_true_payload(self, mock_union_sqli):
        """Test finding best true payload."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        true_response = self._create_mock_response("True response with content")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": true_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        engine = OracleBlindBooleanEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance
        engine._send_payload = lambda inj, p: true_response

        payload = engine.find_best_true_payload(self.injection_point)

        self.assertIsNotNone(payload)

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_find_best_false_payload(self, mock_union_sqli):
        """Test finding best false payload."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        false_response = self._create_mock_response("False response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": false_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        engine = OracleBlindBooleanEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance
        engine._send_payload = lambda inj, p: false_response

        payload = engine.find_best_false_payload(self.injection_point)

        self.assertIsNotNone(payload)

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_detect_content_difference(self, mock_union_sqli):
        """Test detecting content difference."""
        engine = OracleBlindBooleanEngine(self.session, self.base_url)

        true_text = "This is the true response with specific content"
        false_text = "This is the false response with different content"

        result = engine.detect_content_difference(true_text, false_text)

        self.assertTrue(result)

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_detect_length_difference(self, mock_union_sqli):
        """Test detecting length difference."""
        engine = OracleBlindBooleanEngine(self.session, self.base_url)

        true_text = "Short text"
        false_text = "This is a much longer text for the false condition"

        result = engine.detect_length_difference(true_text, false_text)

        self.assertTrue(result)

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_detect_status_difference(self, mock_union_sqli):
        """Test detecting status difference."""
        engine = OracleBlindBooleanEngine(self.session, self.base_url)

        true_response = self._create_mock_response("OK", 200)
        false_response = self._create_mock_response("Error", 500)

        result = engine.detect_status_difference(true_response, false_response)

        self.assertTrue(result)

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_verify_boolean_condition(self, mock_union_sqli):
        """Test verifying boolean condition."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        true_response = self._create_mock_response("True response")
        false_response = self._create_mock_response("False response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_union_sqli.return_value = mock_instance

        engine = OracleBlindBooleanEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance
        engine._send_payload = lambda inj, p: (
            true_response if "1=1" in p else false_response
        )

        verified = engine.verify_boolean_condition(
            self.injection_point, "AND 1=1--", "AND 1=2--"
        )

        self.assertTrue(verified)

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_generate_boolean_payload(self, mock_union_sqli):
        """Test generating boolean payload."""
        engine = OracleBlindBooleanEngine(self.session, self.base_url)

        payload = engine.generate_boolean_payload("1=1")

        self.assertIsNotNone(payload)
        self.assertIn("1=1", payload)

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_is_boolean_vulnerable(self, mock_union_sqli):
        """Test is_boolean_vulnerable convenience method."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        true_response = self._create_mock_response("True response with extra content")
        false_response = self._create_mock_response("False response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_union_sqli.return_value = mock_instance

        engine = OracleBlindBooleanEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance
        engine._send_payload = lambda inj, p: (
            true_response if "1=1" in p else false_response
        )

        is_vuln = engine.is_boolean_vulnerable(self.injection_point)

        self.assertTrue(is_vuln)

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_get_best_boolean_payload(self, mock_union_sqli):
        """Test getting best boolean payload."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        true_response = self._create_mock_response("True response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_union_sqli.return_value = mock_instance

        engine = OracleBlindBooleanEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance
        engine._send_payload = lambda inj, p: true_response

        # Set result manually
        result = BlindBooleanResult(
            success=True, is_vulnerable=True, best_true_payload="'AND 1=1--"
        )
        engine.blind_result = result

        payload = engine.get_best_boolean_payload(self.injection_point)

        self.assertEqual(payload, "'AND 1=1--")

    @patch("app.modules.scanner.blind_boolean.UnionSQLi")
    def test_error_handling(self, mock_union_sqli):
        """Test error handling."""
        mock_instance = Mock()
        mock_instance.get_baseline.side_effect = Exception("Connection error")
        mock_union_sqli.return_value = mock_instance

        engine = OracleBlindBooleanEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance

        result = engine.detect_boolean_blind(self.injection_point)

        self.assertFalse(result.success)
        self.assertGreater(len(result.errors), 0)


if __name__ == "__main__":
    unittest.main()
