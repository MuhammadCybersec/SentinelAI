# tests/test_oracle_privileges.py
"""
Unit tests for Oracle privilege enumeration.
Phase 5: Oracle Privilege Enumeration
"""

import logging
import os
import sys
import unittest
from unittest.mock import Mock, PropertyMock, patch

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.oracle_privileges import (
    OraclePrivilegeEnumerator,
    OraclePrivilegeResult,
)


class TestOraclePrivilegeResult(unittest.TestCase):
    """Test OraclePrivilegeResult data class."""

    def test_privilege_result_initialization(self):
        """Test privilege result initialization."""
        result = OraclePrivilegeResult()

        self.assertFalse(result.success)
        self.assertIsNone(result.current_user)
        self.assertEqual(result.roles, [])
        self.assertEqual(result.system_privileges, [])
        self.assertEqual(result.errors, [])

    def test_add_error(self):
        """Test adding errors."""
        result = OraclePrivilegeResult()
        result.add_error("Test error 1")
        result.add_error("Test error 2")

        self.assertEqual(len(result.errors), 2)
        self.assertEqual(result.errors[0], "Test error 1")

    def test_add_role(self):
        """Test adding roles."""
        result = OraclePrivilegeResult()
        result.add_role("CONNECT")
        result.add_role("RESOURCE")
        result.add_role("CONNECT")  # Duplicate

        self.assertEqual(len(result.roles), 2)
        self.assertIn("CONNECT", result.roles)
        self.assertIn("RESOURCE", result.roles)

    def test_add_system_privilege(self):
        """Test adding system privileges."""
        result = OraclePrivilegeResult()
        result.add_system_privilege("CREATE SESSION")
        result.add_system_privilege("CREATE TABLE")
        result.add_system_privilege("CREATE SESSION")  # Duplicate

        self.assertEqual(len(result.system_privileges), 2)
        self.assertIn("CREATE SESSION", result.system_privileges)
        self.assertIn("CREATE TABLE", result.system_privileges)

    def test_add_session_privilege(self):
        """Test adding session privileges."""
        result = OraclePrivilegeResult()
        result.add_session_privilege("UNLIMITED TABLESPACE")
        result.add_session_privilege("CREATE SESSION")

        self.assertEqual(len(result.session_privileges), 2)

    def test_add_object_privilege(self):
        """Test adding object privileges."""
        result = OraclePrivilegeResult()
        result.add_object_privilege(
            {"owner": "SYS", "table": "DUAL", "privilege": "SELECT"}
        )
        result.add_object_privilege(
            {"owner": "HR", "table": "EMPLOYEES", "privilege": "INSERT"}
        )

        self.assertEqual(len(result.object_privileges), 2)

    def test_get_summary_success(self):
        """Test summary generation on success."""
        result = OraclePrivilegeResult(
            success=True,
            current_user="HR",
            roles=["CONNECT", "RESOURCE"],
            system_privileges=["CREATE SESSION", "CREATE TABLE"],
            is_dba=False,
            is_sysdba=False,
        )

        summary = result.get_summary()
        self.assertIn("User: HR", summary)
        self.assertIn("Roles: 2", summary)
        self.assertIn("System Privs: 2", summary)

    def test_get_summary_with_dba(self):
        """Test summary generation with DBA."""
        result = OraclePrivilegeResult(
            success=True,
            current_user="SYS",
            is_dba=True,
            is_sysdba=True,
            is_sysoper=False,
        )

        summary = result.get_summary()
        self.assertIn("DBA", summary)
        self.assertIn("SYSDBA", summary)

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = OraclePrivilegeResult(success=False)
        summary = result.get_summary()
        self.assertEqual(summary, "Privilege enumeration failed")

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = OraclePrivilegeResult(success=True, current_user="HR", is_dba=False)
        result.add_role("CONNECT")

        data = result.to_dict()

        self.assertEqual(data["success"], True)
        self.assertEqual(data["current_user"], "HR")
        self.assertEqual(data["is_dba"], False)
        self.assertIn("summary", data)


class TestOraclePrivilegeEnumerator(unittest.TestCase):
    """Test Oracle privilege enumerator."""

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

    @patch("app.modules.scanner.oracle_privileges.UnionSQLi")
    def test_enumerate_current_user(self, mock_union_sqli):
        """Test enumerating current user."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        user_response = self._create_mock_response("HR")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": user_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OraclePrivilegeEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        # Patch the _try_payloads method directly
        def mock_try_payloads(inj, payloads, pattern, single=True):
            return "HR"

        enumerator._try_payloads = mock_try_payloads

        result = enumerator.enumerate_current_user(self.injection_point)
        self.assertEqual(result, "HR")

    @patch("app.modules.scanner.oracle_privileges.UnionSQLi")
    def test_enumerate_roles(self, mock_union_sqli):
        """Test enumerating roles."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        roles_response = self._create_mock_response("CONNECT RESOURCE DBA")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": roles_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OraclePrivilegeEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_try_payloads(inj, payloads, pattern, single=False):
            return ["CONNECT", "RESOURCE", "DBA"]

        enumerator._try_payloads = mock_try_payloads

        roles = enumerator.enumerate_roles(self.injection_point)
        self.assertGreater(len(roles), 0)
        self.assertIn("CONNECT", roles)

    @patch("app.modules.scanner.oracle_privileges.UnionSQLi")
    def test_enumerate_system_privileges(self, mock_union_sqli):
        """Test enumerating system privileges."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        privs_response = self._create_mock_response(
            "CREATE SESSION CREATE TABLE CREATE VIEW"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": privs_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OraclePrivilegeEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_try_payloads(inj, payloads, pattern, single=False):
            return ["CREATE SESSION", "CREATE TABLE", "CREATE VIEW"]

        enumerator._try_payloads = mock_try_payloads

        privileges = enumerator.enumerate_system_privileges(self.injection_point)
        self.assertGreater(len(privileges), 0)
        self.assertIn("CREATE SESSION", privileges)

    @patch("app.modules.scanner.oracle_privileges.UnionSQLi")
    def test_enumerate_session_privileges(self, mock_union_sqli):
        """Test enumerating session privileges."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        privs_response = self._create_mock_response(
            "UNLIMITED TABLESPACE CREATE SESSION"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": privs_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OraclePrivilegeEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_try_payloads(inj, payloads, pattern, single=False):
            return ["UNLIMITED TABLESPACE", "CREATE SESSION"]

        enumerator._try_payloads = mock_try_payloads

        privileges = enumerator.enumerate_session_privileges(self.injection_point)
        self.assertGreater(len(privileges), 0)

    @patch("app.modules.scanner.oracle_privileges.UnionSQLi")
    def test_check_dba_true(self, mock_union_sqli):
        """Test checking DBA status - true."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        dba_response = self._create_mock_response("DBA")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": dba_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OraclePrivilegeEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_try_payloads(inj, payloads, pattern, single=True):
            return "DBA"

        enumerator._try_payloads = mock_try_payloads

        is_dba = enumerator.check_dba(self.injection_point)
        self.assertTrue(is_dba)

    @patch("app.modules.scanner.oracle_privileges.UnionSQLi")
    def test_check_dba_false(self, mock_union_sqli):
        """Test checking DBA status - false."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        dba_response = self._create_mock_response("No data")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": dba_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OraclePrivilegeEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_try_payloads(inj, payloads, pattern, single=True):
            return None

        enumerator._try_payloads = mock_try_payloads

        is_dba = enumerator.check_dba(self.injection_point)
        self.assertFalse(is_dba)

    @patch("app.modules.scanner.oracle_privileges.UnionSQLi")
    def test_enumerate_all(self, mock_union_sqli):
        """Test complete privilege enumeration."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        info_response = self._create_mock_response("HR")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": info_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OraclePrivilegeEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        # Override all enumeration methods to return test data
        enumerator.enumerate_current_user = lambda x: "HR"
        enumerator.enumerate_current_schema = lambda x: "HR"
        enumerator.enumerate_session_user = lambda x: "HR"
        enumerator.enumerate_database_user = lambda x: "HR"
        enumerator.enumerate_user_id = lambda x: 12345
        enumerator.enumerate_authentication_type = lambda x: "PASSWORD"
        enumerator.enumerate_default_tablespace = lambda x: "USERS"
        enumerator.enumerate_temporary_tablespace = lambda x: "TEMP"
        enumerator.enumerate_profile = lambda x: "DEFAULT"
        enumerator.enumerate_account_status = lambda x: "OPEN"
        enumerator.enumerate_roles = lambda x: ["CONNECT", "RESOURCE"]
        enumerator.enumerate_session_roles = lambda x: ["CONNECT"]
        enumerator.enumerate_system_privileges = lambda x: [
            "CREATE SESSION",
            "CREATE TABLE",
        ]
        enumerator.enumerate_session_privileges = lambda x: ["UNLIMITED TABLESPACE"]
        enumerator.enumerate_object_privileges = lambda x: []
        enumerator.check_dba = lambda x: False
        enumerator.check_sysdba = lambda x: False
        enumerator.check_sysoper = lambda x: False

        result = enumerator.enumerate_all(self.injection_point)

        self.assertTrue(result.success)
        self.assertEqual(result.current_user, "HR")
        self.assertEqual(len(result.roles), 2)
        self.assertEqual(len(result.system_privileges), 2)

    @patch("app.modules.scanner.oracle_privileges.UnionSQLi")
    def test_handle_permission_denied(self, mock_union_sqli):
        """Test handling permission denied."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        error_response = self._create_mock_response(
            "ORA-01031: insufficient privileges"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": error_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OraclePrivilegeEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_try_payloads(inj, payloads, pattern, single=True):
            return None

        enumerator._try_payloads = mock_try_payloads

        # Should not crash on permission denied
        result = enumerator.enumerate_current_user(self.injection_point)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
