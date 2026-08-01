# tests/test_oracle_detection.py
"""
Unit tests for Oracle detection module.
Phase 1: Oracle Detection
"""

import logging
import os
import sys
import unittest
from unittest.mock import Mock, PropertyMock, patch

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.oracle_enum import DetectionResult, OracleEnum
from app.modules.scanner.payloads import OracleDetectionPayloads

# ============================================================
# TEST CLASS 1: Payload Tests
# ============================================================


class TestOracleDetectionPayloads(unittest.TestCase):
    """Test Oracle detection payloads."""

    def setUp(self):
        self.payloads = OracleDetectionPayloads()

    def test_payload_count(self):
        """Test that we have a reasonable number of payloads."""
        all_payloads = self.payloads.get_all_payloads()
        self.assertGreater(len(all_payloads), 5)

    def test_payload_weights(self):
        """Test that all payloads have weights."""
        for payload in self.payloads.get_all_payloads():
            self.assertGreater(payload.weight, 0)
            self.assertLessEqual(payload.weight, 50)

    def test_payload_filtering(self):
        """Test filtering payloads by weight."""
        heavy_payloads = self.payloads.get_payloads_by_weight(20)
        self.assertGreater(len(heavy_payloads), 0)
        for payload in heavy_payloads:
            self.assertGreaterEqual(payload.weight, 20)


# ============================================================
# TEST CLASS 2: Detection Logic Tests
# ============================================================


class TestOracleEnumDetection(unittest.TestCase):
    """Test Oracle detection functionality."""

    def setUp(self):
        """Set up test environment."""
        # Disable logging during tests
        logging.disable(logging.CRITICAL)

        # Create mock session
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
        # Mock len() to work on response.text
        type(mock_response).text = PropertyMock(return_value=text)
        return mock_response

    @patch("app.modules.scanner.oracle_enum.UnionSQLi")
    def test_detection_success(self, mock_union_sqli):
        """Test successful Oracle detection."""
        # Mock UnionSQLi behavior
        mock_instance = Mock()

        # Create proper mock responses
        baseline_response = self._create_mock_response("Baseline response")
        payload_response = self._create_mock_response("Response with Oracle data")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": payload_response,
            "has_changed": True,
            "status_code": 200,
            "content_length": 100,
        }
        mock_union_sqli.return_value = mock_instance

        # Create OracleEnum with mocked union_sqli
        oracle_enum = OracleEnum(self.session, self.base_url)
        oracle_enum.union_sqli = mock_instance

        # Run detection
        result = oracle_enum.detect(self.injection_point)

        # Assertions
        self.assertTrue(result.is_oracle)
        self.assertGreater(result.score, 0)

    def test_detection_score_threshold(self):
        """Test that detection score meets threshold."""
        result = DetectionResult(threshold=50)
        result.add_indicator("test1", 30)
        result.add_indicator("test2", 25)
        result.is_oracle = result.score >= result.threshold

        self.assertTrue(result.is_oracle)
        self.assertEqual(result.score, 55)

    def test_detection_score_below_threshold(self):
        """Test that score below threshold doesn't detect Oracle."""
        result = DetectionResult(threshold=50)
        result.add_indicator("test1", 10)
        result.add_indicator("test2", 15)
        result.is_oracle = result.score >= result.threshold

        self.assertFalse(result.is_oracle)
        self.assertEqual(result.score, 25)

    @patch("app.modules.scanner.oracle_enum.UnionSQLi")
    def test_detection_with_oracle_errors(self, mock_union_sqli):
        """Test detection with Oracle error indicators."""
        mock_instance = Mock()

        # Create proper mock responses
        baseline_response = self._create_mock_response("Baseline response")
        error_response = self._create_mock_response(
            "ORA-00933: SQL command not properly ended"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": error_response,
            "has_changed": True,
            "status_code": 200,
            "content_length": 100,
        }
        mock_union_sqli.return_value = mock_instance

        # Create OracleEnum with mocked union_sqli
        oracle_enum = OracleEnum(self.session, self.base_url)
        oracle_enum.union_sqli = mock_instance

        # Run detection
        result = oracle_enum.detect(self.injection_point)

        # Should detect Oracle
        self.assertTrue(result.is_oracle)

    def test_indicator_weights(self):
        """Test that indicator weights are properly configured."""
        weights = OracleEnum.INDICATOR_WEIGHTS
        self.assertIn("page_title_oracle", weights)
        self.assertIn("v$version_success", weights)
        self.assertIn("oracle_error", weights)
        self.assertIn("dual_success", weights)

        # v$version should have highest weight
        self.assertGreater(weights["v$version_success"], weights["page_title_oracle"])
        self.assertGreater(weights["oracle_error"], weights["dual_success"])

    # ============================================================
    # FIXED TEST: Detection Result Summary
    # ============================================================

    def test_detection_result_summary(self):
        """Test detection result summary generation."""
        # Test 1: Indicators only (no initial score)
        result = DetectionResult(is_oracle=True, threshold=50)
        result.add_indicator("test1", 30)
        result.add_indicator("test2", 35)
        # Total score should be 65 (30 + 35)

        summary = result.get_summary()
        self.assertIn("Oracle detected", summary)
        self.assertIn("65", summary)
        self.assertEqual(result.score, 65)

        # Test 2: With initial score + indicators
        result2 = DetectionResult(is_oracle=True, score=10, threshold=50)
        result2.add_indicator("test1", 30)
        result2.add_indicator("test2", 35)
        # Total score should be 75 (10 + 30 + 35)

        summary2 = result2.get_summary()
        self.assertIn("Oracle detected", summary2)
        self.assertIn("75", summary2)
        self.assertEqual(result2.score, 75)

        # Test 3: Failure case
        result3 = DetectionResult(is_oracle=False, threshold=50)
        result3.add_indicator("test1", 10)
        result3.add_indicator("test2", 15)
        # Total score should be 25

        summary3 = result3.get_summary()
        self.assertIn("Oracle not detected", summary3)
        self.assertIn("25", summary3)
        self.assertEqual(result3.score, 25)

    # ============================================================
    # FIXED TEST: Detection Result Serialization
    # ============================================================

    def test_detection_result_serialization(self):
        """Test detection result to dict conversion."""
        # Test 1: Indicators only
        result = DetectionResult(threshold=50)
        result.add_indicator("test", 20)
        result.is_oracle = True
        result.reason = "Test reason"
        # Score should be 20

        data = result.to_dict()
        self.assertEqual(data["is_oracle"], True)
        self.assertEqual(data["score"], 20)
        self.assertEqual(data["threshold"], 50)
        self.assertIn("test", data["indicators"])
        self.assertEqual(data["reason"], "Test reason")

        # Test 2: With initial score + indicators
        result2 = DetectionResult(
            is_oracle=True, score=55, threshold=50, reason="Test reason"
        )
        result2.add_indicator("test", 20)
        # Score should be 75 (55 + 20)

        data2 = result2.to_dict()
        self.assertEqual(data2["is_oracle"], True)
        self.assertEqual(data2["score"], 75)
        self.assertEqual(data2["threshold"], 50)
        self.assertIn("test", data2["indicators"])
        self.assertEqual(data2["reason"], "Test reason")

        # Test 3: No indicators
        result3 = DetectionResult(is_oracle=False, threshold=50)
        data3 = result3.to_dict()
        self.assertEqual(data3["is_oracle"], False)
        self.assertEqual(data3["score"], 0)
        self.assertEqual(data3["threshold"], 50)
        self.assertEqual(data3["indicators"], {})

    # ============================================================
    # NEW TEST: Consistency Check
    # ============================================================

    def test_detection_result_consistency(self):
        """Test that summary and to_dict report the same score."""
        result = DetectionResult(is_oracle=True, score=10, threshold=50)
        result.add_indicator("test1", 20)
        result.add_indicator("test2", 15)
        # Total: 10 + 20 + 15 = 45

        # Check consistency
        self.assertEqual(result.score, 45)

        # Summary should contain the score
        summary = result.get_summary()
        self.assertIn("45", summary)

        # to_dict should contain the same score
        data = result.to_dict()
        self.assertEqual(data["score"], 45)

        # Both should match
        self.assertEqual(result.score, data["score"])


# ============================================================
# TEST CLASS 3: Integration Tests
# ============================================================


class TestOracleEnumIntegration(unittest.TestCase):
    """Integration tests for Oracle detection."""

    def _create_mock_response(self, text: str, status_code: int = 200):
        """Helper to create a proper mock response."""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = status_code
        mock_response.text = text
        mock_response.url = "http://test.com"
        type(mock_response).text = PropertyMock(return_value=text)
        return mock_response

    @patch("app.modules.scanner.oracle_enum.UnionSQLi")
    def test_is_oracle_method(self, mock_union_sqli):
        """Test the is_oracle convenience method."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        payload_response = self._create_mock_response("Oracle response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": payload_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        oracle_enum = OracleEnum(Mock(), "http://test.com")
        oracle_enum.union_sqli = mock_instance
        result = oracle_enum.is_oracle("id")

        self.assertTrue(result)

    @patch("app.modules.scanner.oracle_enum.UnionSQLi")
    def test_get_detection_score(self, mock_union_sqli):
        """Test getting detection score without re-running detection."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        payload_response = self._create_mock_response("Oracle response")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": payload_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        oracle_enum = OracleEnum(Mock(), "http://test.com")
        oracle_enum.union_sqli = mock_instance

        # First call runs detection
        score1 = oracle_enum.get_detection_score("id")
        self.assertGreater(score1, 0)

        # Second call should use cached result
        score2 = oracle_enum.get_detection_score("id")
        self.assertEqual(score1, score2)


if __name__ == "__main__":
    unittest.main()
