# tests/test_waf_detector.py
"""
Unit tests for WAF Detection & Fingerprinting Engine.
Phase 14: WAF Detection
"""

import unittest
import logging
from unittest.mock import Mock, patch, PropertyMock
import requests

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.waf_detector import WAFDetector, WAFDetectionResult


class TestWAFDetectionResult(unittest.TestCase):
    """Test WAFDetectionResult data class."""

    def test_result_initialization(self):
        """Test result initialization."""
        result = WAFDetectionResult()

        self.assertFalse(result.success)
        self.assertFalse(result.waf_detected)
        self.assertIsNone(result.waf_name)
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.fingerprints, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.evidence, [])

    def test_add_error(self):
        """Test adding errors."""
        result = WAFDetectionResult()
        result.add_error("Error 1")
        result.add_error("Error 2")

        self.assertEqual(len(result.errors), 2)
        self.assertEqual(result.errors[0], "Error 1")

    def test_add_evidence(self):
        """Test adding evidence."""
        result = WAFDetectionResult()
        result.add_evidence("Evidence 1")
        result.add_evidence("Evidence 2")
        result.add_evidence("Evidence 1")  # Duplicate

        self.assertEqual(len(result.evidence), 2)
        self.assertIn("Evidence 1", result.evidence)

    def test_add_fingerprint(self):
        """Test adding fingerprint."""
        result = WAFDetectionResult()
        result.add_fingerprint("Header: Cloudflare")
        result.add_fingerprint("Body: Cloudflare")

        self.assertEqual(len(result.fingerprints), 2)

    def test_add_bypass_recommendation(self):
        """Test adding bypass recommendation."""
        result = WAFDetectionResult()
        result.add_bypass_recommendation("Use URL encoding")
        result.add_bypass_recommendation("Use comment injection")

        self.assertEqual(len(result.bypass_recommendations), 2)

    def test_get_summary_success_with_waf(self):
        """Test summary generation with WAF detected."""
        result = WAFDetectionResult(
            success=True,
            waf_detected=True,
            waf_name="Cloudflare",
            vendor="Cloudflare",
            confidence=85,
            risk_level="HIGH",
        )
        result.add_fingerprint("CF-Ray")

        summary = result.get_summary()
        self.assertIn("WAF: Cloudflare", summary)
        self.assertIn("Vendor: Cloudflare", summary)
        self.assertIn("Confidence: 85%", summary)
        self.assertIn("Risk: HIGH", summary)

    def test_get_summary_success_no_waf(self):
        """Test summary generation with no WAF."""
        result = WAFDetectionResult(success=True, waf_detected=False)

        summary = result.get_summary()
        self.assertEqual(summary, "No WAF detected")

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = WAFDetectionResult(success=False)
        summary = result.get_summary()
        self.assertEqual(summary, "WAF detection failed")

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = WAFDetectionResult(
            success=True, waf_detected=True, waf_name="Cloudflare", confidence=85
        )
        result.add_evidence("Test evidence")

        data = result.to_dict()

        self.assertEqual(data["success"], True)
        self.assertEqual(data["waf_detected"], True)
        self.assertEqual(data["waf_name"], "Cloudflare")
        self.assertEqual(data["confidence"], 85)
        self.assertIn("summary", data)


class TestWAFDetector(unittest.TestCase):
    """Test WAF Detector."""

    def setUp(self):
        """Set up test environment."""
        logging.disable(logging.CRITICAL)

        self.session = Mock(spec=requests.Session)
        self.base_url = "http://test-target.com/page?id=1"
        self.injection_point = "id"

    def tearDown(self):
        """Clean up after tests."""
        logging.disable(logging.NOTSET)

    def _create_mock_response(
        self, text: str, status_code: int = 200, headers: dict = None
    ):
        """Helper to create a proper mock response."""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = status_code
        mock_response.text = text
        mock_response.url = self.base_url
        mock_response.headers = headers or {}
        type(mock_response).text = PropertyMock(return_value=text)
        return mock_response

    def _create_detector_with_response(self, response):
        """Helper to create a detector with a mocked response."""
        detector = WAFDetector(self.session, self.base_url)

        # Override _get_baseline to return the response
        def mock_get_baseline():
            return response

        detector._get_baseline = mock_get_baseline

        # Override _detect_by_payload to return not blocked
        def mock_detect_payload(inj, payload):
            return {"blocked": False, "response": None}

        detector._detect_by_payload = mock_detect_payload

        return detector

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_detect_cloudflare(self, mock_union_sqli):
        """Test detecting Cloudflare WAF."""
        headers = {
            "Server": "cloudflare",
            "CF-Ray": "123456789",
            "CF-Cache-Status": "HIT",
            "Set-Cookie": "__cfduid=test",
        }
        response = self._create_mock_response("Cloudflare", 200, headers)

        mock_union_sqli.return_value = Mock()

        detector = self._create_detector_with_response(response)

        result = detector.detect(self.injection_point)

        self.assertTrue(result.success)
        self.assertTrue(result.waf_detected)
        # Cloudflare should be detected from headers
        self.assertEqual(result.waf_name, "Cloudflare")

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_detect_imperva(self, mock_union_sqli):
        """Test detecting Imperva WAF."""
        headers = {
            "Server": "Imperva",
            "X-Imperva-Agent": "test",
            "Set-Cookie": "visid_incap=test",
        }
        response = self._create_mock_response("Incapsula", 200, headers)

        mock_union_sqli.return_value = Mock()

        detector = self._create_detector_with_response(response)

        result = detector.detect(self.injection_point)

        self.assertTrue(result.success)
        self.assertTrue(result.waf_detected)
        self.assertEqual(result.waf_name, "Imperva SecureSphere")

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_detect_modsecurity(self, mock_union_sqli):
        """Test detecting ModSecurity WAF."""
        headers = {"Server": "ModSecurity", "X-ModSecurity": "test"}
        response = self._create_mock_response(
            "ModSecurity: Access denied", 403, headers
        )

        mock_union_sqli.return_value = Mock()

        detector = self._create_detector_with_response(response)

        result = detector.detect(self.injection_point)

        self.assertTrue(result.success)
        self.assertTrue(result.waf_detected)
        self.assertEqual(result.waf_name, "ModSecurity")

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_detect_sucuri(self, mock_union_sqli):
        """Test detecting Sucuri WAF."""
        headers = {"Server": "Sucuri", "X-Sucuri": "test", "X-Sucuri-Cache": "HIT"}
        response = self._create_mock_response("Sucuri CloudProxy", 200, headers)

        mock_union_sqli.return_value = Mock()

        detector = self._create_detector_with_response(response)

        result = detector.detect(self.injection_point)

        self.assertTrue(result.success)
        self.assertTrue(result.waf_detected)
        self.assertEqual(result.waf_name, "Sucuri")

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_detect_aws_waf(self, mock_union_sqli):
        """Test detecting AWS WAF."""
        headers = {"Server": "Amazon", "X-Amzn-RequestId": "test"}
        response = self._create_mock_response("AWS WAF", 403, headers)

        mock_union_sqli.return_value = Mock()

        detector = self._create_detector_with_response(response)

        result = detector.detect(self.injection_point)

        self.assertTrue(result.success)
        self.assertTrue(result.waf_detected)
        self.assertEqual(result.waf_name, "AWS WAF")

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_detect_no_waf(self, mock_union_sqli):
        """Test when no WAF is detected."""
        headers = {"Server": "Apache"}
        response = self._create_mock_response("Normal response", 200, headers)

        mock_union_sqli.return_value = Mock()

        detector = self._create_detector_with_response(response)

        result = detector.detect(self.injection_point)

        self.assertTrue(result.success)
        self.assertFalse(result.waf_detected)
        self.assertIsNone(result.waf_name)

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_detect_by_payload_blocked(self, mock_union_sqli):
        """Test payload blocked by WAF."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline", 200, {})
        blocked_response = self._create_mock_response("Blocked", 403, {})

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": blocked_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        detector = WAFDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.detect_by_payload(self.injection_point, "' OR 1=1--")

        self.assertTrue(result["blocked"])
        self.assertEqual(result["status_code"], 403)

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_detect_by_payload_not_blocked(self, mock_union_sqli):
        """Test payload not blocked by WAF."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline", 200, {})
        normal_response = self._create_mock_response("Normal response", 200, {})

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": normal_response,
            "has_changed": False,
        }
        mock_union_sqli.return_value = mock_instance

        detector = WAFDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        result = detector.detect_by_payload(self.injection_point, "' OR 1=1--")

        self.assertFalse(result["blocked"])

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_detect_by_headers(self, mock_union_sqli):
        """Test detecting by headers."""
        headers = {"Server": "cloudflare", "CF-Ray": "test"}
        response = self._create_mock_response("", 200, headers)

        detector = WAFDetector(self.session, self.base_url)

        result = detector.detect_by_headers(response)

        self.assertIn("Cloudflare", result)

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_detect_by_body(self, mock_union_sqli):
        """Test detecting by body."""
        response = self._create_mock_response("ModSecurity: Access denied", 403, {})

        detector = WAFDetector(self.session, self.base_url)

        result = detector.detect_by_body(response)

        self.assertIn("ModSecurity", result)

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_detect_by_status_code(self, mock_union_sqli):
        """Test detecting by status code."""
        response = self._create_mock_response("", 403, {})

        detector = WAFDetector(self.session, self.base_url)

        result = detector.detect_by_status(response)

        self.assertTrue(result)

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_detect_by_block_page(self, mock_union_sqli):
        """Test detecting by block page."""
        response = self._create_mock_response("Access Denied by firewall", 403, {})

        detector = WAFDetector(self.session, self.base_url)

        result = detector.detect_by_block_page(response)

        self.assertTrue(result)

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_calculate_confidence(self, mock_union_sqli):
        """Test confidence calculation."""
        detector = WAFDetector(self.session, self.base_url)

        # High confidence
        confidence = detector.calculate_confidence(3, 3, 2, True)
        self.assertEqual(confidence, 100)

        # Medium confidence
        confidence = detector.calculate_confidence(1, 1, 1, True)
        self.assertEqual(confidence, 55)

        # Low confidence
        confidence = detector.calculate_confidence(0, 0, 0, False)
        self.assertEqual(confidence, 0)

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_get_bypass_recommendations(self, mock_union_sqli):
        """Test getting bypass recommendations."""
        headers = {"Server": "cloudflare", "CF-Ray": "test"}
        response = self._create_mock_response("Cloudflare", 200, headers)

        mock_union_sqli.return_value = Mock()

        detector = self._create_detector_with_response(response)

        recommendations = detector.get_bypass_recommendations(self.injection_point)

        self.assertGreater(len(recommendations), 0)

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_is_waf_present(self, mock_union_sqli):
        """Test is_waf_present convenience method."""
        headers = {"Server": "cloudflare", "CF-Ray": "test"}
        response = self._create_mock_response("Cloudflare", 200, headers)

        mock_union_sqli.return_value = Mock()

        detector = self._create_detector_with_response(response)

        is_present = detector.is_waf_present(self.injection_point)

        self.assertTrue(is_present)

    @patch("app.modules.scanner.waf_detector.UnionSQLi")
    def test_error_handling(self, mock_union_sqli):
        """Test error handling."""
        mock_instance = Mock()
        mock_instance.session = Mock()
        mock_instance.session.get.side_effect = Exception("Connection error")
        mock_union_sqli.return_value = mock_instance

        detector = WAFDetector(self.session, self.base_url)
        detector.union_sqli = mock_instance

        # Override _get_baseline to return None (simulating failure)
        def mock_get_baseline():
            return None

        detector._get_baseline = mock_get_baseline

        result = detector.detect(self.injection_point)

        self.assertFalse(result.success)
        self.assertGreater(len(result.errors), 0)


if __name__ == "__main__":
    unittest.main()
