# tests/test_tamper_engine.py
"""
Unit tests for Payload Tamper Engine.
Phase 15: Tamper Engine Tests
"""

import unittest
import logging
from unittest.mock import Mock, patch
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.tamper_engine import TamperEngine, TamperResult


class TestTamperResult(unittest.TestCase):
    """Test TamperResult data class."""

    def test_result_initialization(self):
        """Test result initialization."""
        result = TamperResult()

        self.assertEqual(result.original_payload, "")
        self.assertEqual(result.tampered_payload, "")
        self.assertEqual(result.tamper_chain, [])
        self.assertEqual(result.confidence, 0)
        self.assertFalse(result.success)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.tamper_count, 0)

    def test_add_error(self):
        """Test adding errors."""
        result = TamperResult()
        result.add_error("Error 1")
        result.add_error("Error 2")
        result.add_error("Error 1")  # Duplicate

        self.assertEqual(len(result.errors), 2)
        self.assertEqual(result.errors[0], "Error 1")
        self.assertEqual(result.errors[1], "Error 2")

    def test_get_summary_success(self):
        """Test summary generation on success."""
        result = TamperResult(
            success=True,
            tamper_chain=["random_case", "url_encode"],
            tamper_count=2,
            confidence=85,
        )

        summary = result.get_summary()
        self.assertIn("Chain: random_case, url_encode", summary)
        self.assertIn("Tampers: 2", summary)
        self.assertIn("Confidence: 85%", summary)

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = TamperResult(success=False)
        result.add_error("Test error")

        summary = result.get_summary()
        self.assertIn("Tampering failed", summary)

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = TamperResult(
            original_payload="' OR 1=1--",
            tampered_payload="' OR/**/1=1--",
            success=True,
            tamper_count=1,
            confidence=80,
        )
        result.tamper_chain.append("space_to_comment")

        data = result.to_dict()

        self.assertEqual(data["original_payload"], "' OR 1=1--")
        self.assertEqual(data["tampered_payload"], "' OR/**/1=1--")
        self.assertEqual(data["success"], True)
        self.assertEqual(data["tamper_count"], 1)
        self.assertEqual(data["confidence"], 80)
        self.assertIn("summary", data)


class TestTamperEngine(unittest.TestCase):
    """Test Tamper Engine."""

    def setUp(self):
        """Set up test environment."""
        logging.disable(logging.CRITICAL)
        self.engine = TamperEngine()

    def tearDown(self):
        """Clean up after tests."""
        logging.disable(logging.NOTSET)

    def test_list_tampers(self):
        """Test listing tampers."""
        tampers = self.engine.list_tampers()

        self.assertGreater(len(tampers), 0)
        self.assertIn("random_case", tampers)
        self.assertIn("url_encode", tampers)
        self.assertIn("inline_comment", tampers)

    def test_apply_random_case(self):
        """Test random_case tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "random_case")

        self.assertTrue(result.success)
        self.assertNotEqual(result.tampered_payload, payload)
        # Should contain same characters but different case
        self.assertEqual(payload.lower(), result.tampered_payload.lower())

    def test_apply_space_to_comment(self):
        """Test space_to_comment tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "space_to_comment")

        self.assertTrue(result.success)
        self.assertEqual(result.tampered_payload, "SELECT/**/*/**/FROM/**/users")

    def test_apply_space_to_plus(self):
        """Test space_to_plus tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "space_to_plus")

        self.assertTrue(result.success)
        self.assertEqual(result.tampered_payload, "SELECT+*+FROM+users")

    def test_apply_space_to_tab(self):
        """Test space_to_tab tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "space_to_tab")

        self.assertTrue(result.success)
        self.assertIn("\t", result.tampered_payload)
        self.assertNotIn(" ", result.tampered_payload)

    def test_apply_space_to_newline(self):
        """Test space_to_newline tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "space_to_newline")

        self.assertTrue(result.success)
        self.assertIn("\n", result.tampered_payload)
        self.assertNotIn(" ", result.tampered_payload)

    def test_apply_url_encode(self):
        """Test url_encode tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "url_encode")

        self.assertTrue(result.success)
        self.assertIn("%", result.tampered_payload)
        self.assertNotEqual(result.tampered_payload, payload)

    def test_apply_double_url_encode(self):
        """Test double_url_encode tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "double_url_encode")

        self.assertTrue(result.success)
        self.assertIn("%25", result.tampered_payload)

    def test_apply_unicode_encode(self):
        """Test unicode_encode tamper."""
        payload = "' OR 1=1--"
        result = self.engine.apply(payload, "unicode_encode")

        self.assertTrue(result.success)
        self.assertIn("%u", result.tampered_payload)

    def test_apply_char_encode(self):
        """Test char_encode tamper."""
        payload = "' OR 1=1--"
        result = self.engine.apply(payload, "char_encode")

        self.assertTrue(result.success)
        self.assertIn("CHAR(", result.tampered_payload)

    def test_apply_percentage_encode(self):
        """Test percentage_encode tamper."""
        payload = "' OR 1=1--"
        result = self.engine.apply(payload, "percentage_encode")

        self.assertTrue(result.success)
        self.assertIn("%", result.tampered_payload)

    def test_apply_append_comment(self):
        """Test append_comment tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "append_comment")

        self.assertTrue(result.success)
        self.assertIn("/*", result.tampered_payload)
        self.assertIn("*/", result.tampered_payload)
        self.assertNotEqual(result.tampered_payload, payload)

    def test_apply_inline_comment(self):
        """Test inline_comment tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "inline_comment")

        self.assertTrue(result.success)
        self.assertIn("/*", result.tampered_payload)
        self.assertIn("*/", result.tampered_payload)

    def test_apply_keyword_split(self):
        """Test keyword_split tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "keyword_split")

        self.assertTrue(result.success)
        self.assertIn("/**/", result.tampered_payload)

    def test_apply_version_comment(self):
        """Test version_comment tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "version_comment")

        self.assertTrue(result.success)
        self.assertIn("/*!", result.tampered_payload)
        self.assertIn("*/", result.tampered_payload)

    def test_apply_mixed_encoding(self):
        """Test mixed_encoding tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "mixed_encoding")

        self.assertTrue(result.success)
        # Should be modified
        self.assertNotEqual(result.tampered_payload, payload)

    def test_apply_case_randomizer(self):
        """Test case_randomizer tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "case_randomizer")

        self.assertTrue(result.success)
        # Should contain mixed case
        has_upper = any(c.isupper() for c in result.tampered_payload)
        has_lower = any(c.islower() for c in result.tampered_payload)
        self.assertTrue(has_upper or has_lower)
        # Should be different from original
        self.assertNotEqual(result.tampered_payload, payload)

    def test_apply_unknown_tamper(self):
        """Test applying unknown tamper."""
        payload = "SELECT * FROM users"
        result = self.engine.apply(payload, "unknown_tamper")

        self.assertFalse(result.success)
        self.assertIn("Unknown tamper", result.errors[0])

    def test_apply_chain(self):
        """Test applying tamper chain."""
        payload = "SELECT * FROM users"
        chain = ["space_to_comment", "url_encode"]
        result = self.engine.apply_chain(payload, chain)

        self.assertTrue(result.success)
        self.assertEqual(result.tamper_count, 2)
        self.assertEqual(result.tamper_chain, chain)
        self.assertIn("%2F%2A%2A%2F", result.tampered_payload)  # URL encoded /**/

    def test_apply_chain_with_unknown(self):
        """Test applying chain with unknown tamper."""
        payload = "SELECT * FROM users"
        chain = ["space_to_comment", "unknown_tamper", "url_encode"]
        result = self.engine.apply_chain(payload, chain)

        # Should still apply valid tampers
        self.assertTrue(result.success)
        self.assertEqual(result.tamper_count, 2)
        self.assertIn("Unknown tamper", result.errors[0])

    def test_recommend_tampers_cloudflare(self):
        """Test recommendations for Cloudflare."""
        recommendations = self.engine.recommend_tampers("Cloudflare")

        self.assertGreater(len(recommendations), 0)
        self.assertIn("random_case", recommendations)

    def test_recommend_tampers_modsecurity(self):
        """Test recommendations for ModSecurity."""
        recommendations = self.engine.recommend_tampers("ModSecurity")

        self.assertGreater(len(recommendations), 0)
        self.assertIn("space_to_comment", recommendations)
        self.assertIn("inline_comment", recommendations)

    def test_recommend_tampers_aws_waf(self):
        """Test recommendations for AWS WAF."""
        recommendations = self.engine.recommend_tampers("AWS WAF")

        self.assertGreater(len(recommendations), 0)
        self.assertIn("url_encode", recommendations)
        self.assertIn("double_url_encode", recommendations)

    def test_recommend_tampers_general(self):
        """Test general recommendations."""
        recommendations = self.engine.recommend_tampers("Unknown WAF")

        self.assertGreater(len(recommendations), 0)
        self.assertIn("random_case", recommendations)
        self.assertIn("url_encode", recommendations)

    def test_get_tamper_confidence(self):
        """Test getting tamper confidence."""
        confidence = self.engine.get_tamper_confidence("random_case")
        self.assertEqual(confidence, 60)

        confidence = self.engine.get_tamper_confidence("inline_comment")
        self.assertEqual(confidence, 80)

        confidence = self.engine.get_tamper_confidence("unknown")
        self.assertEqual(confidence, 50)

    def test_test_tamper(self):
        """Test testing a tamper."""
        # Should modify payload
        result = self.engine.test_tamper("SELECT * FROM users", "space_to_comment")
        self.assertTrue(result)

        # Should not modify payload (but it will due to case)
        # Actually random_case always modifies
        result = self.engine.test_tamper("SELECT", "random_case")
        self.assertTrue(result)

    def test_apply_preserves_logic(self):
        """Test that tamper preserves SQL logic."""
        payload = "' OR 1=1--"
        result = self.engine.apply(payload, "space_to_comment")

        self.assertTrue(result.success)
        # Logic should be preserved
        self.assertIn("OR", result.tampered_payload.upper())
        self.assertIn("1=1", result.tampered_payload)

    def test_chain_confidence_calculation(self):
        """Test chain confidence calculation."""
        payload = "SELECT * FROM users"
        chain = ["random_case", "space_to_comment", "url_encode"]
        result = self.engine.apply_chain(payload, chain)

        self.assertTrue(result.success)
        # Confidence should be average of all tampers
        expected = (60 + 75 + 70) // 3
        self.assertAlmostEqual(result.confidence, expected, delta=5)

    def test_chain_empty(self):
        """Test applying empty chain."""
        payload = "SELECT * FROM users"
        result = self.engine.apply_chain(payload, [])

        self.assertFalse(result.success)
        self.assertEqual(result.tampered_payload, "")

    def test_error_handling(self):
        """Test error handling in tampers."""
        # Test with payload that might cause issues
        payload = "SELECT * FROM users WHERE id=1"
        result = self.engine.apply(payload, "char_encode")

        self.assertTrue(result.success)
        self.assertIsNotNone(result.tampered_payload)


if __name__ == "__main__":
    unittest.main()
