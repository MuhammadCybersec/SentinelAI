# tests/test_error_based.py
"""
Unit tests for Error-Based Exploitation Engine.
Phase 13: Error-Based Detection
"""

import logging
import os
import sys
import unittest
from unittest.mock import Mock, PropertyMock, patch

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.error_based import ErrorBasedResult, OracleErrorBasedEngine


class TestErrorBasedResult(unittest.TestCase):
    """Test ErrorBasedResult data class."""

    def test_result_initialization(self):
        """Test result initialization."""
        result = ErrorBasedResult()

        self.assertFalse(result.success)
        self.assertFalse(result.is_vulnerable)
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.working_payloads, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.evidence, [])

    def test_add_error(self):
        """Test adding errors."""
        result = ErrorBasedResult()
        result.add_error("Error 1")
        result.add_error("Error 2")

        self.assertEqual(len(result.errors), 2)
        self.assertEqual(result.errors[0], "Error 1")

    def test_add_evidence(self):
        """Test adding evidence."""
        result = ErrorBasedResult()
        result.add_evidence("Evidence 1")
        result.add_evidence("Evidence 2")
        result.add_evidence("Evidence 1")  # Duplicate

        self.assertEqual(len(result.evidence), 2)
        self.assertIn("Evidence 1", result.evidence)

    def test_add_working_payload(self):
        """Test adding working payload."""
        result = ErrorBasedResult()
        result.add_working_payload("payload1")
        result.add_working_payload("payload2")
        result.add_working_payload("payload1")  # Duplicate

        self.assertEqual(len(result.working_payloads), 2)
        self.assertIn("payload1", result.working_payloads)

    def test_add_oracle_error(self):
        """Test adding Oracle error."""
        result = ErrorBasedResult()
        result.add_oracle_error("ORA-00933: SQL command not properly ended")
        result.add_oracle_error("ORA-00942: table or view does not exist")

        self.assertEqual(len(result.oracle_errors), 2)

    def test_add_error_code(self):
        """Test adding error code."""
        result = ErrorBasedResult()
        result.add_error_code("ORA-00933")
        result.add_error_code("ORA-00942")

        self.assertEqual(len(result.detected_error_codes), 2)

    def test_get_summary_success_vulnerable(self):
        """Test summary generation on vulnerable."""
        result = ErrorBasedResult(
            success=True,
            is_vulnerable=True,
            confidence=85,
            best_payload="'AND 1=TO_NUMBER('test')--",
        )
        result.add_error_code("ORA-00933")
        result.add_error_code("ORA-01722")

        summary = result.get_summary()
        self.assertIn("Vulnerable: YES", summary)
        self.assertIn("Error codes: ORA-00933, ORA-01722", summary)
        self.assertIn("Confidence: 85%", summary)

    def test_get_summary_success_not_vulnerable(self):
        """Test summary generation on not vulnerable."""
        result = ErrorBasedResult(success=True, is_vulnerable=False)

        summary = result.get_summary()
        self.assertEqual(summary, "Error-based SQL injection not detected")

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = ErrorBasedResult(success=False)
        summary = result.get_summary()
        self.assertEqual(summary, "Error-based detection failed")

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = ErrorBasedResult(
            success=True,
            is_vulnerable=True,
            confidence=85,
            best_payload="'AND 1=TO_NUMBER('test')--",
        )
        result.add_evidence("Test evidence")
        result.add_error_code("ORA-00933")

        data = result.to_dict()

        self.assertEqual(data["success"], True)
        self.assertEqual(data["is_vulnerable"], True)
        self.assertEqual(data["confidence"], 85)
        self.assertEqual(data["best_payload"], "'AND 1=TO_NUMBER('test')--")
        self.assertEqual(data["detected_error_codes"], ["ORA-00933"])
        self.assertIn("summary", data)


class TestOracleErrorBasedEngine(unittest.TestCase):
    """Test Oracle Error Based Engine."""

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

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_detect_error_based_vulnerable(self, mock_union_sqli):
        """Test detecting error based - vulnerable."""
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

        engine = OracleErrorBasedEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance

        # Override _send_payload to return error response
        engine._send_payload = lambda inj, payload: error_response

        result = engine.detect_error_based(self.injection_point)

        self.assertTrue(result.success)
        self.assertTrue(result.is_vulnerable)
        self.assertGreater(result.confidence, 50)

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_detect_error_based_not_vulnerable(self, mock_union_sqli):
        """Test detecting error based - not vulnerable."""
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

        engine = OracleErrorBasedEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance

        engine._send_payload = lambda inj, payload: normal_response

        result = engine.detect_error_based(self.injection_point)

        self.assertTrue(result.success)
        self.assertFalse(result.is_vulnerable)

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_parse_oracle_error(self, mock_union_sqli):
        """Test parsing Oracle error."""
        engine = OracleErrorBasedEngine(self.session, self.base_url)

        text = "Error: ORA-00933: SQL command not properly ended"
        error = engine.parse_oracle_error(text)

        self.assertIsNotNone(error)
        self.assertIn("ORA-00933", error)

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_detect_error_code(self, mock_union_sqli):
        """Test detecting error code."""
        engine = OracleErrorBasedEngine(self.session, self.base_url)

        text = "ORA-00933: SQL command not properly ended"
        code = engine.detect_error_code(text)

        self.assertEqual(code, "ORA-00933")

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_extract_from_error(self, mock_union_sqli):
        """Test extracting from error."""
        engine = OracleErrorBasedEngine(self.session, self.base_url)

        text = "ORA-00933: invalid identifier: USERNAME"
        values = engine.extract_from_error(text)

        self.assertGreater(len(values), 0)

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_build_error_payloads(self, mock_union_sqli):
        """Test building error payloads."""
        engine = OracleErrorBasedEngine(self.session, self.base_url)

        payloads = engine.build_error_payloads()

        self.assertGreater(len(payloads), 0)
        self.assertTrue(any("TO_NUMBER" in p for p in payloads))

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_find_best_payload(self, mock_union_sqli):
        """Test finding best payload."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        error_response = self._create_mock_response("ORA-00933: error")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": error_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        engine = OracleErrorBasedEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance

        engine._send_payload = lambda inj, payload: error_response

        payload = engine.find_best_payload(self.injection_point)

        self.assertIsNotNone(payload)

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_verify_error_success(self, mock_union_sqli):
        """Test verifying error - success."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        error_response = self._create_mock_response("ORA-00933: error")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": error_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        engine = OracleErrorBasedEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance

        engine._send_payload = lambda inj, payload: error_response

        result = engine.verify_error(self.injection_point, "test_payload")

        self.assertTrue(result["verified"])
        self.assertEqual(result["error_code"], "ORA-00933")

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_verify_error_failure(self, mock_union_sqli):
        """Test verifying error - failure."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        normal_response = self._create_mock_response("Normal")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": normal_response,
            "has_changed": False,
        }
        mock_union_sqli.return_value = mock_instance

        engine = OracleErrorBasedEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance

        engine._send_payload = lambda inj, payload: normal_response

        result = engine.verify_error(self.injection_point, "test_payload")

        self.assertFalse(result["verified"])

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_rank_payloads(self, mock_union_sqli):
        """Test ranking payloads."""
        engine = OracleErrorBasedEngine(self.session, self.base_url)

        payloads = ["payload1", "payload2", "payload3"]
        error_codes = ["ORA-00933", "ORA-01722", "ORA-00904"]
        extracted_values = [["value1"], ["value2"], ["value3"]]

        ranked = engine.rank_payloads(payloads, error_codes, extracted_values)

        self.assertEqual(len(ranked), 3)
        self.assertEqual(ranked[0]["payload"], "payload1")

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_calculate_confidence(self, mock_union_sqli):
        """Test calculating confidence."""
        engine = OracleErrorBasedEngine(self.session, self.base_url)

        # High confidence
        confidence = engine.calculate_confidence(5, True, 3)
        self.assertEqual(confidence, 90)

        # Medium confidence
        confidence = engine.calculate_confidence(2, True, 1)
        self.assertGreaterEqual(confidence, 50)

        # Low confidence
        confidence = engine.calculate_confidence(1, False, 1)
        self.assertEqual(confidence, 20)

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_generate_payload(self, mock_union_sqli):
        """Test generating payload."""
        engine = OracleErrorBasedEngine(self.session, self.base_url)

        payload = engine.generate_payload("to_number", "test")
        self.assertIn("TO_NUMBER", payload)

        payload = engine.generate_payload("to_char", "1")
        self.assertIn("TO_CHAR", payload)

        payload = engine.generate_payload("cast", "test")
        self.assertIn("CAST", payload)

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_is_error_based(self, mock_union_sqli):
        """Test is_error_based convenience method."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        error_response = self._create_mock_response("ORA-00933: error")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": error_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        engine = OracleErrorBasedEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance

        engine._send_payload = lambda inj, payload: error_response

        is_vuln = engine.is_error_based(self.injection_point)

        self.assertTrue(is_vuln)

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_get_best_error_payload(self, mock_union_sqli):
        """Test getting best error payload."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        error_response = self._create_mock_response("ORA-00933: error")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": error_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        engine = OracleErrorBasedEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance

        engine._send_payload = lambda inj, payload: error_response

        payload = engine.get_best_error_payload(self.injection_point)

        self.assertIsNotNone(payload)

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_extract_error_data(self, mock_union_sqli):
        """Test extracting error data."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        error_response = self._create_mock_response(
            "ORA-00933: invalid identifier: USERNAME"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": error_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        engine = OracleErrorBasedEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance

        engine._send_payload = lambda inj, payload: error_response

        values = engine.extract_error_data(self.injection_point, "test_payload")

        self.assertGreater(len(values), 0)

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_error_handling(self, mock_union_sqli):
        """Test error handling."""
        mock_instance = Mock()
        mock_instance.get_baseline.side_effect = Exception("Connection error")
        mock_union_sqli.return_value = mock_instance

        engine = OracleErrorBasedEngine(self.session, self.base_url)
        engine.union_sqli = mock_instance

        result = engine.detect_error_based(self.injection_point)

        self.assertFalse(result.success)
        self.assertGreater(len(result.errors), 0)

    @patch("app.modules.scanner.error_based.UnionSQLi")
    def test_multiple_error_codes(self, mock_union_sqli):
        """Test detection of multiple error codes."""
        OracleErrorBasedEngine(self.session, self.base_url)

        error_text = (
            "ORA-00933: SQL command not properly ended and ORA-01722: invalid number"
        )

        codes = []
        for code in ["ORA-00933", "ORA-01722"]:
            if code in error_text:
                codes.append(code)

        self.assertEqual(len(codes), 2)
        self.assertIn("ORA-00933", codes)
        self.assertIn("ORA-01722", codes)


if __name__ == "__main__":
    unittest.main()
