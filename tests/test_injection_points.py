# tests/test_injection_points.py
"""
Unit tests for Injection Point Discovery.
Phase 8: Injection Point Discovery
"""

import unittest
import logging
from unittest.mock import Mock, patch, PropertyMock
import requests
import json

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.injection_points import (
    InjectionPointDiscovery,
    InjectionPointResult,
    InjectionDiscoveryResult,
)


class TestInjectionPointResult(unittest.TestCase):
    """Test InjectionPointResult data class."""

    def test_result_initialization(self):
        """Test result initialization."""
        result = InjectionPointResult(
            parameter_name="id", parameter_type="GET", original_value="1"
        )

        self.assertEqual(result.parameter_name, "id")
        self.assertEqual(result.parameter_type, "GET")
        self.assertEqual(result.original_value, "1")
        self.assertFalse(result.is_injectable)
        self.assertEqual(result.evidence, [])

    def test_add_evidence(self):
        """Test adding evidence."""
        result = InjectionPointResult()
        result.add_evidence("Evidence 1")
        result.add_evidence("Evidence 2")
        result.add_evidence("Evidence 1")  # Duplicate

        self.assertEqual(len(result.evidence), 2)
        self.assertIn("Evidence 1", result.evidence)

    def test_get_summary(self):
        """Test summary generation."""
        result = InjectionPointResult(
            parameter_name="id",
            parameter_type="GET",
            original_value="1",
            is_injectable=True,
            confidence=85,
        )

        summary = result.get_summary()
        self.assertIn("GET::id", summary)
        self.assertIn("INJECTABLE", summary)
        self.assertIn("85%", summary)

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = InjectionPointResult(
            parameter_name="id",
            parameter_type="GET",
            original_value="1",
            is_injectable=True,
            confidence=85,
        )
        result.add_evidence("Test evidence")

        data = result.to_dict()

        self.assertEqual(data["parameter_name"], "id")
        self.assertEqual(data["parameter_type"], "GET")
        self.assertEqual(data["is_injectable"], True)
        self.assertEqual(data["confidence"], 85)
        self.assertIn("summary", data)


class TestInjectionDiscoveryResult(unittest.TestCase):
    """Test InjectionDiscoveryResult data class."""

    def test_result_initialization(self):
        """Test result initialization."""
        result = InjectionDiscoveryResult()

        self.assertFalse(result.success)
        self.assertEqual(result.parameters, [])
        self.assertEqual(result.total_parameters, 0)
        self.assertEqual(result.injectable_parameters, 0)
        self.assertEqual(result.errors, [])

    def test_add_parameter(self):
        """Test adding parameters."""
        result = InjectionDiscoveryResult()

        param1 = InjectionPointResult(
            parameter_name="id", parameter_type="GET", is_injectable=True, confidence=80
        )
        param2 = InjectionPointResult(
            parameter_name="name",
            parameter_type="POST",
            is_injectable=False,
            confidence=20,
        )

        result.add_parameter(param1)
        result.add_parameter(param2)

        self.assertEqual(result.total_parameters, 2)
        self.assertEqual(result.injectable_parameters, 1)
        self.assertEqual(len(result.parameters), 2)

    def test_add_error(self):
        """Test adding errors."""
        result = InjectionDiscoveryResult()
        result.add_error("Error 1")
        result.add_error("Error 2")

        self.assertEqual(len(result.errors), 2)

    def test_get_best_parameter(self):
        """Test getting best parameter."""
        result = InjectionDiscoveryResult()

        param1 = InjectionPointResult(
            parameter_name="id", parameter_type="GET", is_injectable=True, confidence=85
        )
        param2 = InjectionPointResult(
            parameter_name="name",
            parameter_type="POST",
            is_injectable=True,
            confidence=70,
        )
        param3 = InjectionPointResult(
            parameter_name="email",
            parameter_type="JSON",
            is_injectable=False,
            confidence=30,
        )

        result.add_parameter(param1)
        result.add_parameter(param2)
        result.add_parameter(param3)

        best = result.get_best_parameter()
        self.assertEqual(best.parameter_name, "id")
        self.assertEqual(best.confidence, 85)

    def test_get_injectable_parameters(self):
        """Test getting injectable parameters."""
        result = InjectionDiscoveryResult()

        param1 = InjectionPointResult(parameter_name="id", is_injectable=True)
        param2 = InjectionPointResult(parameter_name="name", is_injectable=False)
        param3 = InjectionPointResult(parameter_name="email", is_injectable=True)

        result.add_parameter(param1)
        result.add_parameter(param2)
        result.add_parameter(param3)

        injectable = result.get_injectable_parameters()
        self.assertEqual(len(injectable), 2)
        self.assertEqual(injectable[0].parameter_name, "id")
        self.assertEqual(injectable[1].parameter_name, "email")

    def test_get_summary(self):
        """Test summary generation."""
        result = InjectionDiscoveryResult(success=True)

        param = InjectionPointResult(
            parameter_name="id", is_injectable=True, confidence=85
        )
        result.add_parameter(param)
        result.add_parameter(
            InjectionPointResult(parameter_name="name", is_injectable=False)
        )

        summary = result.get_summary()
        self.assertIn("Total parameters: 2", summary)
        self.assertIn("Injectable: 1", summary)
        self.assertIn("id", summary)

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = InjectionDiscoveryResult(success=True)

        param = InjectionPointResult(
            parameter_name="id", is_injectable=True, confidence=85
        )
        result.add_parameter(param)

        data = result.to_dict()

        self.assertEqual(data["success"], True)
        self.assertEqual(data["total_parameters"], 1)
        self.assertEqual(data["injectable_parameters"], 1)
        self.assertIn("summary", data)


class TestInjectionPointDiscovery(unittest.TestCase):
    """Test Injection Point Discovery."""

    def setUp(self):
        """Set up test environment."""
        logging.disable(logging.CRITICAL)

        self.session = Mock(spec=requests.Session)
        self.base_url = "http://test-target.com/page?id=1&name=test"
        self.injection_point = "id"

    def tearDown(self):
        """Clean up after tests."""
        logging.disable(logging.NOTSET)

    def test_discover_get_parameters(self):
        """Test discovering GET parameters."""
        discovery = InjectionPointDiscovery(self.session, self.base_url)

        results = discovery.discover_get_parameters(self.base_url)

        self.assertGreater(len(results), 0)
        param_names = [r.parameter_name for r in results]
        self.assertIn("id", param_names)
        self.assertIn("name", param_names)

    def test_discover_post_parameters(self):
        """Test discovering POST parameters."""
        discovery = InjectionPointDiscovery(self.session, self.base_url)

        post_data = {"username": "admin", "password": "pass123", "action": "login"}
        results = discovery.discover_post_parameters(post_data)

        self.assertEqual(len(results), 3)
        param_names = [r.parameter_name for r in results]
        self.assertIn("username", param_names)
        self.assertIn("password", param_names)
        self.assertIn("action", param_names)

    def test_discover_json_parameters(self):
        """Test discovering JSON parameters."""
        discovery = InjectionPointDiscovery(self.session, self.base_url)

        json_data = {
            "user": {"id": 1, "name": "John", "profile": {"age": 30, "city": "NYC"}},
            "items": [1, 2, 3],
        }

        results = discovery.discover_json_parameters(json_data)

        self.assertGreater(len(results), 0)
        param_names = [r.parameter_name for r in results]
        self.assertIn("user.id", param_names)
        self.assertIn("user.name", param_names)
        self.assertIn("user.profile.age", param_names)
        self.assertIn("user.profile.city", param_names)
        self.assertIn("items[0]", param_names)
        self.assertIn("items[1]", param_names)
        self.assertIn("items[2]", param_names)

    def test_discover_xml_parameters(self):
        """Test discovering XML parameters."""
        discovery = InjectionPointDiscovery(self.session, self.base_url)

        xml_data = """
        <root>
            <user id="123">
                <name>John</name>
                <email>john@test.com</email>
                <profile age="30" city="NYC"/>
            </user>
        </root>
        """

        results = discovery.discover_xml_parameters(xml_data)

        self.assertGreater(len(results), 0)
        param_names = [r.parameter_name for r in results]
        self.assertIn("root.user@id", param_names)
        self.assertIn("root.user.name", param_names)
        self.assertIn("root.user.email", param_names)
        self.assertIn("root.user.profile@age", param_names)
        self.assertIn("root.user.profile@city", param_names)

    def test_discover_cookie_parameters(self):
        """Test discovering cookie parameters."""
        discovery = InjectionPointDiscovery(self.session, self.base_url)

        cookies = {
            "session_id": "abc123",
            "user_pref": "dark_mode",
            "auth_token": "xyz789",
        }

        results = discovery.discover_cookie_parameters(cookies)

        self.assertEqual(len(results), 3)
        param_names = [r.parameter_name for r in results]
        self.assertIn("session_id", param_names)
        self.assertIn("user_pref", param_names)
        self.assertIn("auth_token", param_names)

    def test_discover_header_parameters(self):
        """Test discovering header parameters."""
        discovery = InjectionPointDiscovery(self.session, self.base_url)

        headers = {
            "User-Agent": "Mozilla/5.0",
            "Referer": "http://google.com",
            "X-Forwarded-For": "127.0.0.1",
            "Accept-Language": "en-US",
            "Normal-Header": "test",
        }

        results = discovery.discover_header_parameters(headers)

        self.assertGreater(len(results), 0)
        param_names = [r.parameter_name for r in results]
        self.assertIn("User-Agent", param_names)
        self.assertIn("Referer", param_names)
        self.assertIn("X-Forwarded-For", param_names)

    def test_test_parameter(self):
        """Test testing a parameter."""
        discovery = InjectionPointDiscovery(self.session, self.base_url)

        param = InjectionPointResult(
            parameter_name="id", parameter_type="GET", original_value="1"
        )

        tested = discovery.test_parameter(param, "1'")

        self.assertTrue(tested.is_injectable)
        self.assertGreater(tested.confidence, 0)
        self.assertGreater(len(tested.evidence), 0)

    def test_discover_all(self):
        """Test complete discovery."""
        discovery = InjectionPointDiscovery(self.session, self.base_url)

        result = discovery.discover_all(
            url=self.base_url,
            data={"username": "admin", "password": "pass123"},
            json_data={"user": {"id": 1, "name": "John"}},
            cookies={"session_id": "abc123"},
            headers={"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "127.0.0.1"},
            test_parameters=False,
        )

        self.assertTrue(result.success)
        self.assertGreater(result.total_parameters, 0)

    def test_discover_all_with_testing(self):
        """Test complete discovery with parameter testing."""
        discovery = InjectionPointDiscovery(self.session, self.base_url)

        result = discovery.discover_all(
            url=self.base_url,
            data={"username": "admin", "password": "pass123"},
            test_parameters=True,
        )

        self.assertTrue(result.success)
        self.assertGreater(result.total_parameters, 0)

        # Some parameters should be marked injectable
        injectable = result.get_injectable_parameters()
        self.assertGreater(len(injectable), 0)

    def test_get_best_parameter(self):
        """Test getting best parameter after discovery."""
        discovery = InjectionPointDiscovery(self.session, self.base_url)

        discovery.discover_all(url=self.base_url, test_parameters=False)

        best = discovery.get_best_parameter()
        self.assertIsNotNone(best)
        # The best parameter should be either 'id' or 'name'
        # Both have high confidence due to being suspicious
        self.assertIn(best.parameter_name, ["id", "name"])
        self.assertEqual(best.parameter_type, "GET")

    def test_count_parameters(self):
        """Test counting parameters."""
        discovery = InjectionPointDiscovery(self.session, self.base_url)

        discovery.discover_all(url=self.base_url, test_parameters=False)

        count = discovery.count_parameters()
        self.assertGreater(count, 0)

    def test_nested_json_with_arrays(self):
        """Test nested JSON with arrays."""
        discovery = InjectionPointDiscovery(self.session, self.base_url)

        json_data = {"users": [{"id": 1, "name": "John"}, {"id": 2, "name": "Jane"}]}

        results = discovery.discover_json_parameters(json_data)

        self.assertGreater(len(results), 0)
        param_names = [r.parameter_name for r in results]
        self.assertIn("users[0].id", param_names)
        self.assertIn("users[0].name", param_names)
        self.assertIn("users[1].id", param_names)
        self.assertIn("users[1].name", param_names)


if __name__ == "__main__":
    unittest.main()
