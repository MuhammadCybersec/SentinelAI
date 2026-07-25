# tests/test_oracle_database.py
"""
Unit tests for Oracle database and environment enumeration.
Phase 6: Oracle Database & Environment Enumeration
"""

import unittest
import logging
from unittest.mock import Mock, patch, PropertyMock
import requests

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.oracle_database import (
    OracleDatabaseEnumerator,
    OracleDatabaseResult,
)


class TestOracleDatabaseResult(unittest.TestCase):
    """Test OracleDatabaseResult data class."""

    def test_database_result_initialization(self):
        """Test database result initialization."""
        result = OracleDatabaseResult()

        self.assertFalse(result.success)
        self.assertIsNone(result.database_name)
        self.assertIsNone(result.instance_name)
        self.assertEqual(result.errors, [])

    def test_add_error(self):
        """Test adding errors."""
        result = OracleDatabaseResult()
        result.add_error("Test error 1")
        result.add_error("Test error 2")

        self.assertEqual(len(result.errors), 2)
        self.assertEqual(result.errors[0], "Test error 1")

    def test_add_component(self):
        """Test adding components."""
        result = OracleDatabaseResult()
        result.add_component("JAVA")
        result.add_component("XML")
        result.add_component("JAVA")  # Duplicate

        self.assertEqual(len(result.installed_components), 2)
        self.assertIn("JAVA", result.installed_components)
        self.assertIn("XML", result.installed_components)

    def test_add_option(self):
        """Test adding options."""
        result = OracleDatabaseResult()
        result.add_option("RAC")
        result.add_option("PARTITIONING")

        self.assertEqual(len(result.installed_options), 2)
        self.assertIn("RAC", result.installed_options)
        self.assertIn("PARTITIONING", result.installed_options)

    def test_add_nls_parameter(self):
        """Test adding NLS parameters."""
        result = OracleDatabaseResult()
        result.add_nls_parameter("NLS_LANGUAGE", "AMERICAN")
        result.add_nls_parameter("NLS_TERRITORY", "AMERICA")

        self.assertEqual(len(result.nls_parameters), 2)
        self.assertEqual(result.nls_parameters["NLS_LANGUAGE"], "AMERICAN")

    def test_get_summary_success(self):
        """Test summary generation on success."""
        result = OracleDatabaseResult(
            success=True,
            database_name="ORCL",
            instance_name="orcl",
            version="19.3.0.0.0",
            edition="Enterprise Edition",
            host_name="server.domain.com",
            database_role="PRIMARY",
            character_set="AL32UTF8",
            is_cdb=True,
        )
        result.add_component("JAVA")

        summary = result.get_summary()
        self.assertIn("Database: ORCL", summary)
        self.assertIn("Instance: orcl", summary)
        self.assertIn("Version: 19.3.0.0.0", summary)
        self.assertIn("Edition: Enterprise Edition", summary)
        self.assertIn("Host: server.domain.com", summary)
        self.assertIn("Role: PRIMARY", summary)
        self.assertIn("Charset: AL32UTF8", summary)
        self.assertIn("CDB", summary)

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = OracleDatabaseResult(success=False)
        summary = result.get_summary()
        self.assertEqual(summary, "Database enumeration failed")

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = OracleDatabaseResult(
            success=True, database_name="ORCL", instance_name="orcl"
        )

        data = result.to_dict()

        self.assertEqual(data["success"], True)
        self.assertEqual(data["database_name"], "ORCL")
        self.assertEqual(data["instance_name"], "orcl")
        self.assertIn("summary", data)


class TestOracleDatabaseEnumerator(unittest.TestCase):
    """Test Oracle database enumerator."""

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

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
    def test_enumerate_banner(self, mock_union_sqli):
        """Test enumerating banner."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        banner_response = self._create_mock_response(
            "Oracle Database 19c Enterprise Edition"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": banner_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_send(inj, payload):
            return banner_response

        enumerator._send_payload = mock_send

        result = enumerator.enumerate_banner(self.injection_point)
        self.assertIsNotNone(result)

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
    def test_enumerate_database_name(self, mock_union_sqli):
        """Test enumerating database name."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        name_response = self._create_mock_response("ORCL")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": name_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_send(inj, payload):
            return name_response

        enumerator._send_payload = mock_send

        result = enumerator.enumerate_database_name(self.injection_point)
        self.assertEqual(result, "ORCL")

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
    def test_enumerate_instance_name(self, mock_union_sqli):
        """Test enumerating instance name."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        instance_response = self._create_mock_response("orcl")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": instance_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_send(inj, payload):
            return instance_response

        enumerator._send_payload = mock_send

        result = enumerator.enumerate_instance_name(self.injection_point)
        self.assertEqual(result, "orcl")

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
    def test_enumerate_version(self, mock_union_sqli):
        """Test enumerating version."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        version_response = self._create_mock_response("Oracle Database 19c 19.3.0.0.0")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": version_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_send(inj, payload):
            return version_response

        enumerator._send_payload = mock_send

        result = enumerator.enumerate_version(self.injection_point)
        self.assertEqual(result, "19.3.0.0.0")

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
    def test_enumerate_hostname(self, mock_union_sqli):
        """Test enumerating hostname."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        host_response = self._create_mock_response("server.domain.com")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": host_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_send(inj, payload):
            return host_response

        enumerator._send_payload = mock_send

        result = enumerator.enumerate_hostname(self.injection_point)
        self.assertEqual(result, "server.domain.com")

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
    def test_enumerate_character_set(self, mock_union_sqli):
        """Test enumerating character set."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        charset_response = self._create_mock_response("AL32UTF8")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": charset_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_send(inj, payload):
            return charset_response

        enumerator._send_payload = mock_send

        result = enumerator.enumerate_character_set(self.injection_point)
        self.assertEqual(result, "AL32UTF8")

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
    def test_enumerate_database_role(self, mock_union_sqli):
        """Test enumerating database role."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        role_response = self._create_mock_response("PRIMARY")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": role_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_send(inj, payload):
            return role_response

        enumerator._send_payload = mock_send

        result = enumerator.enumerate_database_role(self.injection_point)
        self.assertEqual(result, "PRIMARY")

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
    def test_enumerate_cdb(self, mock_union_sqli):
        """Test checking CDB status."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        cdb_response = self._create_mock_response("CDB$ROOT")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": cdb_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_send(inj, payload):
            return cdb_response

        enumerator._send_payload = mock_send

        is_cdb = enumerator.enumerate_cdb(self.injection_point)
        self.assertTrue(is_cdb)

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
    def test_enumerate_cdb_false(self, mock_union_sqli):
        """Test checking CDB status - false."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        cdb_response = self._create_mock_response("No data")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": cdb_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_send(inj, payload):
            return cdb_response

        enumerator._send_payload = mock_send

        is_cdb = enumerator.enumerate_cdb(self.injection_point)
        self.assertFalse(is_cdb)

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
    def test_enumerate_components(self, mock_union_sqli):
        """Test enumerating components."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        comps_response = self._create_mock_response("JAVA XML CATALOG")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": comps_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_send(inj, payload):
            return comps_response

        enumerator._send_payload = mock_send

        components = enumerator.enumerate_components(self.injection_point)
        self.assertGreater(len(components), 0)

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
    def test_enumerate_all(self, mock_union_sqli):
        """Test complete database enumeration."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        info_response = self._create_mock_response("ORCL")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": info_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        # Override methods to return test data
        enumerator.enumerate_banner = lambda x: "Oracle Database 19c Enterprise Edition"
        enumerator.enumerate_database_name = lambda x: "ORCL"
        enumerator.enumerate_instance_name = lambda x: "orcl"
        enumerator.enumerate_sid = lambda x: "ORCL"
        enumerator.enumerate_service_name = lambda x: "orcl.domain.com"
        enumerator.enumerate_hostname = lambda x: "server.domain.com"
        enumerator.enumerate_global_name = lambda x: "orcl.domain.com"
        enumerator.enumerate_oracle_home = (
            lambda x: "/u01/app/oracle/product/19.0.0/dbhome_1"
        )
        enumerator.enumerate_platform = lambda x: "Linux x86_64"
        enumerator.enumerate_operating_system = lambda x: "Linux"
        enumerator.enumerate_version = lambda x: "19.3.0.0.0"
        enumerator.enumerate_database_role = lambda x: "PRIMARY"
        enumerator.enumerate_open_mode = lambda x: "READ WRITE"
        enumerator.enumerate_log_mode = lambda x: "ARCHIVELOG"
        enumerator.enumerate_startup_time = lambda x: "2024-01-01 00:00:00"
        enumerator.enumerate_uptime = lambda x: "30d 12h 30m"
        enumerator.enumerate_current_date = lambda x: "2024-01-31"
        enumerator.enumerate_current_time = lambda x: "12:30:00"
        enumerator.enumerate_timezone = lambda x: "+00:00"
        enumerator.enumerate_character_set = lambda x: "AL32UTF8"
        enumerator.enumerate_national_character_set = lambda x: "AL16UTF16"
        enumerator.enumerate_nls_language = lambda x: "AMERICAN"
        enumerator.enumerate_nls_territory = lambda x: "AMERICA"
        enumerator.enumerate_nls_parameters = lambda x: {"NLS_LANGUAGE": "AMERICAN"}
        enumerator.enumerate_cdb = lambda x: True
        enumerator.enumerate_pdb = lambda x: "PDB1"
        enumerator.enumerate_container_name = lambda x: "CDB$ROOT"
        enumerator.enumerate_components = lambda x: ["JAVA", "XML"]
        enumerator.enumerate_options = lambda x: ["RAC", "PARTITIONING"]
        enumerator.enumerate_edition = lambda x: "Enterprise Edition"
        enumerator.enumerate_full_version = (
            lambda x: "Oracle Database 19c Enterprise Edition Release 19.3.0.0.0"
        )

        result = enumerator.enumerate_all(self.injection_point)

        self.assertTrue(result.success)
        self.assertEqual(result.database_name, "ORCL")
        self.assertEqual(result.instance_name, "orcl")
        self.assertEqual(result.version, "19.3.0.0.0")
        self.assertEqual(result.edition, "Enterprise Edition")
        self.assertTrue(result.is_cdb)
        self.assertEqual(len(result.installed_components), 2)

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
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

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_send(inj, payload):
            return error_response

        enumerator._send_payload = mock_send

        # Should not crash on permission denied
        result = enumerator.enumerate_database_name(self.injection_point)
        self.assertIsNone(result)

    @patch("app.modules.scanner.oracle_database.UnionSQLi")
    def test_handle_missing_view(self, mock_union_sqli):
        """Test handling missing view."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        error_response = self._create_mock_response(
            "ORA-00942: table or view does not exist"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": error_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleDatabaseEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        def mock_send(inj, payload):
            return error_response

        enumerator._send_payload = mock_send

        # Should not crash on missing view
        result = enumerator.enumerate_components(self.injection_point)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
