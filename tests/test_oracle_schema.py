# tests/test_oracle_schema.py
"""
Unit tests for Oracle schema enumeration.
Phase 3: Oracle Schema Enumeration
"""

import logging
import os
import sys
import unittest
from unittest.mock import Mock, PropertyMock, patch

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.oracle_schema import OracleSchemaEnumerator, OracleSchemaResult

# ============================================================
# TEST CLASS 1: Schema Result Tests
# ============================================================


class TestOracleSchemaResult(unittest.TestCase):
    """Test OracleSchemaResult data class."""

    def test_schema_result_initialization(self):
        """Test schema result initialization."""
        result = OracleSchemaResult()

        self.assertFalse(result.success)
        self.assertIsNone(result.current_user)
        self.assertIsNone(result.current_schema)
        self.assertIsNone(result.database_name)
        self.assertIsNone(result.server_host)
        self.assertEqual(result.schemas, [])
        self.assertEqual(result.tables, {})
        self.assertEqual(result.columns, {})
        self.assertEqual(result.errors, [])

    def test_add_error(self):
        """Test adding errors."""
        result = OracleSchemaResult()
        result.add_error("Test error 1")
        result.add_error("Test error 2")

        self.assertEqual(len(result.errors), 2)
        self.assertEqual(result.errors[0], "Test error 1")

    def test_add_table(self):
        """Test adding tables."""
        result = OracleSchemaResult()
        result.add_table("SCHEMA1", "TABLE1")
        result.add_table("SCHEMA1", "TABLE2")
        result.add_table("SCHEMA2", "TABLE3")

        self.assertEqual(len(result.tables["SCHEMA1"]), 2)
        self.assertEqual(len(result.tables["SCHEMA2"]), 1)
        self.assertIn("TABLE1", result.tables["SCHEMA1"])
        self.assertIn("TABLE3", result.tables["SCHEMA2"])

    def test_add_column(self):
        """Test adding columns."""
        result = OracleSchemaResult()
        result.add_column("SCHEMA1", "TABLE1", "COL1")
        result.add_column("SCHEMA1", "TABLE1", "COL2")
        result.add_column("SCHEMA1", "TABLE2", "COL3")

        self.assertEqual(len(result.columns["SCHEMA1"]["TABLE1"]), 2)
        self.assertEqual(len(result.columns["SCHEMA1"]["TABLE2"]), 1)
        self.assertIn("COL1", result.columns["SCHEMA1"]["TABLE1"])
        self.assertIn("COL3", result.columns["SCHEMA1"]["TABLE2"])

    def test_add_index(self):
        """Test adding indexes."""
        result = OracleSchemaResult()
        result.add_index("SCHEMA1", "IDX1")
        result.add_index("SCHEMA1", "IDX2")
        result.add_index("SCHEMA2", "IDX3")

        self.assertEqual(len(result.indexes["SCHEMA1"]), 2)
        self.assertEqual(len(result.indexes["SCHEMA2"]), 1)
        self.assertIn("IDX1", result.indexes["SCHEMA1"])
        self.assertIn("IDX3", result.indexes["SCHEMA2"])

    def test_add_constraint(self):
        """Test adding constraints."""
        result = OracleSchemaResult()
        result.add_constraint("SCHEMA1", "P", "PK1")
        result.add_constraint("SCHEMA1", "P", "PK2")
        result.add_constraint("SCHEMA1", "R", "FK1")

        self.assertEqual(len(result.constraints["SCHEMA1"]["P"]), 2)
        self.assertEqual(len(result.constraints["SCHEMA1"]["R"]), 1)
        self.assertIn("PK1", result.constraints["SCHEMA1"]["P"])
        self.assertIn("FK1", result.constraints["SCHEMA1"]["R"])

    def test_get_summary_success(self):
        """Test summary generation on success."""
        result = OracleSchemaResult(success=True)
        result.current_user = "TESTUSER"
        result.database_name = "TESTDB"
        result.schemas = ["SCHEMA1", "SCHEMA2"]
        result.add_table("SCHEMA1", "TABLE1")
        result.add_table("SCHEMA1", "TABLE2")

        summary = result.get_summary()
        self.assertIn("User: TESTUSER", summary)
        self.assertIn("Database: TESTDB", summary)
        self.assertIn("Schemas: 2", summary)
        self.assertIn("Tables: 2", summary)

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = OracleSchemaResult(success=False)
        summary = result.get_summary()
        self.assertEqual(summary, "Schema enumeration failed")

    def test_get_summary_with_errors(self):
        """Test summary generation with errors."""
        result = OracleSchemaResult(success=True)
        result.add_error("Error 1")
        result.add_error("Error 2")

        summary = result.get_summary()
        self.assertIn("Errors: 2", summary)

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = OracleSchemaResult(
            success=True, current_user="TESTUSER", database_name="TESTDB"
        )
        result.add_table("SCHEMA1", "TABLE1")

        data = result.to_dict()

        self.assertEqual(data["success"], True)
        self.assertEqual(data["current_user"], "TESTUSER")
        self.assertEqual(data["database_name"], "TESTDB")
        self.assertIn("summary", data)
        self.assertEqual(data["tables"]["SCHEMA1"][0], "TABLE1")


# ============================================================
# TEST CLASS 2: Schema Enumerator Tests
# ============================================================


class TestOracleSchemaEnumerator(unittest.TestCase):
    """Test Oracle schema enumerator."""

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

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_enumerate_current_user(self, mock_union_sqli):
        """Test enumerating current user."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        user_response = self._create_mock_response("TESTUSER")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": user_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        result = enumerator.enumerate_current_user(self.injection_point)
        self.assertEqual(result, "TESTUSER")

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_enumerate_current_schema(self, mock_union_sqli):
        """Test enumerating current schema."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        schema_response = self._create_mock_response("TESTSCHEMA")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": schema_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        result = enumerator.enumerate_current_schema(self.injection_point)
        self.assertEqual(result, "TESTSCHEMA")

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_enumerate_database_name(self, mock_union_sqli):
        """Test enumerating database name."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        db_response = self._create_mock_response("TESTDB")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": db_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        result = enumerator.enumerate_database_name(self.injection_point)
        self.assertEqual(result, "TESTDB")

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_enumerate_server_host(self, mock_union_sqli):
        """Test enumerating server host."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        host_response = self._create_mock_response("test-server.domain.com")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": host_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        result = enumerator.enumerate_server_host(self.injection_point)
        self.assertEqual(result, "test-server.domain.com")

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_enumerate_version(self, mock_union_sqli):
        """Test enumerating version."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        version_response = self._create_mock_response(
            "Oracle Database 19c Enterprise Edition Release 19.3.0.0.0"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": version_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        result = enumerator.enumerate_version(self.injection_point)
        self.assertEqual(result, "19.3.0.0.0")

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_enumerate_banner(self, mock_union_sqli):
        """Test enumerating banner."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        banner_response = self._create_mock_response(
            "Oracle Database 19c Enterprise Edition Release 19.3.0.0.0"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": banner_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        result = enumerator.enumerate_banner(self.injection_point)
        self.assertEqual(
            result, "Oracle Database 19c Enterprise Edition Release 19.3.0.0.0"
        )

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_enumerate_schemas(self, mock_union_sqli):
        """Test enumerating schemas."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        schemas_response = self._create_mock_response("SCHEMA1 SCHEMA2 TESTUSER")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": schemas_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        result = enumerator.enumerate_schemas(self.injection_point)
        self.assertGreater(len(result), 0)

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_enumerate_tables(self, mock_union_sqli):
        """Test enumerating tables."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        tables_response = self._create_mock_response("TABLE1 TABLE2 TABLE3")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": tables_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        result = enumerator.enumerate_tables(self.injection_point, "SCHEMA1")
        self.assertGreater(len(result), 0)

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_enumerate_columns(self, mock_union_sqli):
        """Test enumerating columns."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        columns_response = self._create_mock_response("COL1 COL2 COL3")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": columns_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        result = enumerator.enumerate_columns(self.injection_point, "SCHEMA1", "TABLE1")
        self.assertGreater(len(result), 0)

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_enumerate_indexes(self, mock_union_sqli):
        """Test enumerating indexes."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        indexes_response = self._create_mock_response("IDX1 IDX2 IDX3")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": indexes_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        result = enumerator.enumerate_indexes(self.injection_point, "SCHEMA1")
        self.assertGreater(len(result), 0)

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_enumerate_constraints(self, mock_union_sqli):
        """Test enumerating constraints."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        constraints_response = self._create_mock_response("PK1 P, FK1 R, UK1 U")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": constraints_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        result = enumerator.enumerate_constraints(self.injection_point, "SCHEMA1")
        self.assertIn("P", result)
        self.assertIn("R", result)
        self.assertIn("U", result)

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_enumerate_all(self, mock_union_sqli):
        """Test full enumeration."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        info_response = self._create_mock_response("TESTUSER")
        self._create_mock_response("SCHEMA1")
        self._create_mock_response("TABLE1 TABLE2")
        self._create_mock_response("COL1 COL2 COL3")
        self._create_mock_response("IDX1")
        self._create_mock_response("PK1 P")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": info_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        # Override methods to return test data
        enumerator.enumerate_current_user = lambda x: "TESTUSER"
        enumerator.enumerate_current_schema = lambda x: "TESTSCHEMA"
        enumerator.enumerate_database_name = lambda x: "TESTDB"
        enumerator.enumerate_server_host = lambda x: "test-server"
        enumerator.enumerate_version = lambda x: "19.3.0.0.0"
        enumerator.enumerate_banner = lambda x: "Oracle 19c"
        enumerator.enumerate_schemas = lambda x: ["SCHEMA1"]
        enumerator.enumerate_tables = lambda x, y: ["TABLE1", "TABLE2"]
        enumerator.enumerate_columns = lambda x, y, z: ["COL1", "COL2", "COL3"]
        enumerator.enumerate_indexes = lambda x, y: ["IDX1"]
        enumerator.enumerate_constraints = lambda x, y: {"P": ["PK1"]}

        result = enumerator.enumerate_all(self.injection_point)

        self.assertTrue(result.success)
        self.assertEqual(result.current_user, "TESTUSER")
        self.assertEqual(result.database_name, "TESTDB")
        self.assertEqual(len(result.schemas), 1)
        self.assertEqual(len(result.tables), 1)


# ============================================================
# TEST CLASS 3: Convenience Methods
# ============================================================


class TestOracleSchemaConvenience(unittest.TestCase):
    """Test convenience methods."""

    def setUp(self):
        """Set up test environment."""
        logging.disable(logging.CRITICAL)
        self.session = Mock(spec=requests.Session)
        self.base_url = "http://test.com"
        self.injection_point = "id"

    def tearDown(self):
        """Clean up after tests."""
        logging.disable(logging.NOTSET)

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_get_current_user(self, mock_union_sqli):
        """Test get_current_user convenience method."""
        mock_instance = Mock()
        baseline_response = Mock()
        baseline_response.text = "Baseline"
        user_response = Mock()
        user_response.text = "TESTUSER"

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": user_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        result = enumerator.get_current_user(self.injection_point)
        self.assertEqual(result, "TESTUSER")

    @patch("app.modules.scanner.oracle_schema.UnionSQLi")
    def test_get_database_info(self, mock_union_sqli):
        """Test get_database_info convenience method."""
        mock_instance = Mock()
        baseline_response = Mock()
        baseline_response.text = "Baseline"
        info_response = Mock()
        info_response.text = "TESTUSER"

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": info_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        enumerator = OracleSchemaEnumerator(self.session, self.base_url)
        enumerator.union_sqli = mock_instance

        # Override methods
        enumerator.enumerate_current_user = lambda x: "TESTUSER"
        enumerator.enumerate_current_schema = lambda x: "TESTSCHEMA"
        enumerator.enumerate_database_name = lambda x: "TESTDB"
        enumerator.enumerate_server_host = lambda x: "test-server"
        enumerator.enumerate_version = lambda x: "19.3.0.0.0"
        enumerator.enumerate_banner = lambda x: "Oracle 19c"

        info = enumerator.get_database_info(self.injection_point)

        self.assertEqual(info["current_user"], "TESTUSER")
        self.assertEqual(info["database_name"], "TESTDB")
        self.assertEqual(info["version"], "19.3.0.0.0")


if __name__ == "__main__":
    unittest.main()
