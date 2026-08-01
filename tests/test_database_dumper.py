# tests/test_database_dumper.py
"""
Unit tests for Database Dumper.
Phase 17: Database Dumper Tests
"""

import csv
import json
import logging
import os
import sqlite3
import sys
import tempfile
import time  # ADDED
import unittest
from unittest.mock import Mock, PropertyMock, patch

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.database_dumper import DatabaseDumpResult, OracleDatabaseDumper


class TestDatabaseDumpResult(unittest.TestCase):
    """Test DatabaseDumpResult data class."""

    def test_result_initialization(self):
        """Test result initialization."""
        result = DatabaseDumpResult()

        self.assertFalse(result.success)
        self.assertEqual(result.schemas_dumped, 0)
        self.assertEqual(result.tables_dumped, 0)
        self.assertEqual(result.rows_dumped, 0)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.tables, {})

    def test_add_error(self):
        """Test adding errors."""
        result = DatabaseDumpResult()
        result.add_error("Error 1")
        result.add_error("Error 2")

        self.assertEqual(len(result.errors), 2)
        self.assertEqual(result.errors[0], "Error 1")

    def test_add_table_data(self):
        """Test adding table data."""
        result = DatabaseDumpResult()
        rows = [{"COL1": "value1", "COL2": "value2"}]
        result.add_table_data("SCHEMA1", "TABLE1", rows)

        self.assertEqual(result.rows_dumped, 1)
        self.assertEqual(result.table_names, ["SCHEMA1.TABLE1"])
        self.assertIn("SCHEMA1", result.tables)
        self.assertIn("TABLE1", result.tables["SCHEMA1"])

    def test_get_summary_success(self):
        """Test summary generation on success."""
        result = DatabaseDumpResult(
            success=True,
            schemas_dumped=2,
            tables_dumped=5,
            rows_dumped=100,
            dump_time=10.5,
        )

        summary = result.get_summary()
        self.assertIn("Schemas: 2", summary)
        self.assertIn("Tables: 5", summary)
        self.assertIn("Rows: 100", summary)
        self.assertIn("Time: 10.50s", summary)

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = DatabaseDumpResult(success=False)
        summary = result.get_summary()
        self.assertEqual(summary, "Database dump failed")

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = DatabaseDumpResult(
            success=True, schemas_dumped=1, tables_dumped=2, rows_dumped=10
        )
        result.add_error("Test error")

        data = result.to_dict()

        self.assertEqual(data["success"], True)
        self.assertEqual(data["schemas_dumped"], 1)
        self.assertEqual(data["tables_dumped"], 2)
        self.assertEqual(data["rows_dumped"], 10)
        self.assertIn("summary", data)


class TestOracleDatabaseDumper(unittest.TestCase):
    """Test Oracle Database Dumper."""

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

    @patch("app.modules.scanner.database_dumper.OracleSchemaEnumerator")
    def test_discover_targets(self, mock_schema_enumerator):
        """Test discovering targets."""
        mock_instance = Mock()
        mock_instance.enumerate_schemas.return_value = ["SCHEMA1", "SCHEMA2"]
        mock_instance.enumerate_tables.side_effect = [
            ["TABLE1", "TABLE2", "TABLE3"],
            ["TABLE4", "TABLE5"],
        ]
        mock_schema_enumerator.return_value = mock_instance

        dumper = OracleDatabaseDumper(self.session, self.base_url, self.injection_point)
        dumper.schema_enumerator = mock_instance

        result = dumper.discover_targets(max_schemas=2, max_tables=3)

        self.assertEqual(len(result), 2)
        self.assertIn("SCHEMA1", result)
        self.assertIn("SCHEMA2", result)
        self.assertEqual(len(result["SCHEMA1"]), 3)
        self.assertEqual(len(result["SCHEMA2"]), 2)

    @patch("app.modules.scanner.database_dumper.OracleDataExtractor")
    def test_dump_table(self, mock_data_extractor):
        """Test dumping a table."""
        mock_instance = Mock()
        mock_extract_result = Mock()
        mock_extract_result.success = True
        mock_extract_result.rows = [
            {"COL1": "value1", "COL2": "value2"},
            {"COL1": "value3", "COL2": "value4"},
        ]
        mock_instance.extract_table.return_value = mock_extract_result
        mock_data_extractor.return_value = mock_instance

        dumper = OracleDatabaseDumper(self.session, self.base_url, self.injection_point)
        dumper.data_extractor = mock_instance

        result = dumper.dump_table("SCHEMA1", "TABLE1")

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["COL1"], "value1")

    @patch("app.modules.scanner.database_dumper.OracleDataExtractor")
    def test_dump_table_failure(self, mock_data_extractor):
        """Test dumping a table - failure."""
        mock_instance = Mock()
        mock_extract_result = Mock()
        mock_extract_result.success = False
        mock_extract_result.rows = []
        mock_instance.extract_table.return_value = mock_extract_result
        mock_data_extractor.return_value = mock_instance

        dumper = OracleDatabaseDumper(self.session, self.base_url, self.injection_point)
        dumper.data_extractor = mock_instance

        result = dumper.dump_table("SCHEMA1", "TABLE1")

        self.assertEqual(result, [])

    @patch("app.modules.scanner.database_dumper.OracleSchemaEnumerator")
    @patch("app.modules.scanner.database_dumper.OracleDataExtractor")
    def test_dump_schema(self, mock_data_extractor, mock_schema_enumerator):
        """Test dumping a schema."""
        mock_schema = Mock()
        mock_schema.enumerate_tables.return_value = ["TABLE1", "TABLE2"]
        mock_schema_enumerator.return_value = mock_schema

        mock_extract = Mock()
        mock_extract_result = Mock()
        mock_extract_result.success = True
        mock_extract_result.rows = [{"COL1": "value1"}]
        mock_extract.extract_table.return_value = mock_extract_result
        mock_data_extractor.return_value = mock_extract

        dumper = OracleDatabaseDumper(self.session, self.base_url, self.injection_point)
        dumper.schema_enumerator = mock_schema
        dumper.data_extractor = mock_extract

        result = dumper.dump_schema("SCHEMA1")

        self.assertEqual(len(result), 2)
        self.assertIn("TABLE1", result)
        self.assertIn("TABLE2", result)

    @patch("app.modules.scanner.database_dumper.OracleSchemaEnumerator")
    @patch("app.modules.scanner.database_dumper.OracleDataExtractor")
    def test_dump_multiple_tables(self, mock_data_extractor, mock_schema_enumerator):
        """Test dumping multiple tables."""
        mock_extract = Mock()
        mock_extract_result = Mock()
        mock_extract_result.success = True
        mock_extract_result.rows = [{"COL1": "value1"}]
        mock_extract.extract_table.return_value = mock_extract_result
        mock_data_extractor.return_value = mock_extract

        dumper = OracleDatabaseDumper(self.session, self.base_url, self.injection_point)
        dumper.data_extractor = mock_extract

        result = dumper.dump_multiple_tables("SCHEMA1", ["TABLE1", "TABLE2"])

        self.assertEqual(len(result), 2)
        self.assertIn("TABLE1", result)
        self.assertIn("TABLE2", result)

    @patch("app.modules.scanner.database_dumper.OracleSchemaEnumerator")
    @patch("app.modules.scanner.database_dumper.OracleDataExtractor")
    def test_dump_database(self, mock_data_extractor, mock_schema_enumerator):
        """Test full database dump."""
        mock_schema = Mock()
        mock_schema.enumerate_schemas.return_value = ["SCHEMA1"]
        mock_schema.enumerate_tables.return_value = ["TABLE1", "TABLE2"]
        mock_schema_enumerator.return_value = mock_schema

        mock_extract = Mock()
        mock_extract_result = Mock()
        mock_extract_result.success = True
        mock_extract_result.rows = [{"COL1": "value1"}]
        mock_extract.extract_table.return_value = mock_extract_result
        mock_data_extractor.return_value = mock_extract

        dumper = OracleDatabaseDumper(self.session, self.base_url, self.injection_point)
        dumper.schema_enumerator = mock_schema
        dumper.data_extractor = mock_extract

        result = dumper.dump_database(max_schemas=1, max_tables=2)

        self.assertTrue(result.success)
        self.assertEqual(result.schemas_dumped, 1)
        self.assertEqual(result.tables_dumped, 2)
        self.assertEqual(result.rows_dumped, 2)

    @patch("app.modules.scanner.database_dumper.OracleSchemaEnumerator")
    def test_blacklist_filtering(self, mock_schema_enumerator):
        """Test blacklist filtering."""
        mock_instance = Mock()
        mock_instance.enumerate_schemas.return_value = ["SCHEMA1"]
        mock_instance.enumerate_tables.return_value = [
            "USERS",
            "SYS_TABLE",
            "EMPLOYEES",
        ]
        mock_schema_enumerator.return_value = mock_instance

        dumper = OracleDatabaseDumper(self.session, self.base_url, self.injection_point)
        dumper.schema_enumerator = mock_instance

        blacklist = {"SYS_TABLE"}
        result = dumper.discover_targets(blacklist=blacklist)

        tables = result.get("SCHEMA1", [])
        self.assertIn("USERS", tables)
        self.assertIn("EMPLOYEES", tables)
        self.assertNotIn("SYS_TABLE", tables)

    @patch("app.modules.scanner.database_dumper.OracleSchemaEnumerator")
    def test_sensitive_table_prioritization(self, mock_schema_enumerator):
        """Test sensitive table prioritization."""
        mock_instance = Mock()
        mock_instance.enumerate_schemas.return_value = ["SCHEMA1"]
        mock_instance.enumerate_tables.return_value = [
            "LOGS",
            "USERS",
            "AUDIT",
            "EMPLOYEES",
        ]
        mock_schema_enumerator.return_value = mock_instance

        dumper = OracleDatabaseDumper(self.session, self.base_url, self.injection_point)
        dumper.schema_enumerator = mock_instance

        # Override the _get_priority_tables method for testing
        def mock_priority(tables):
            # USERS should come first
            if "USERS" in tables:
                return ["USERS", "EMPLOYEES", "AUDIT", "LOGS"]
            return tables

        dumper._get_priority_tables = mock_priority

        result = dumper.discover_targets(prioritize_sensitive=True)

        tables = result.get("SCHEMA1", [])
        # Sensitive tables should come first
        self.assertEqual(tables[0], "USERS")
        self.assertEqual(tables[1], "EMPLOYEES")

    def test_track_progress(self):
        """Test progress tracking."""

        dumper = OracleDatabaseDumper(self.session, self.base_url, self.injection_point)

        dumper.current_progress["total_tables"] = 10
        dumper.current_progress["completed_tables"] = 5
        dumper.current_progress["total_rows"] = 100
        dumper.current_progress["dumped_rows"] = 50
        dumper.current_progress["start_time"] = time.time()
        dumper.current_progress["elapsed_time"] = 10

        progress = dumper.track_progress()

        self.assertEqual(progress["percentage"], 50.0)

    @patch("app.modules.scanner.database_dumper.OracleSchemaEnumerator")
    @patch("app.modules.scanner.database_dumper.OracleDataExtractor")
    def test_export_json(self, mock_data_extractor, mock_schema_enumerator):
        """Test JSON export."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = DatabaseDumpResult(
                success=True, schemas_dumped=1, tables_dumped=1, rows_dumped=1
            )
            result.add_table_data("SCHEMA1", "TABLE1", [{"COL1": "value1"}])

            dumper = OracleDatabaseDumper(
                self.session, self.base_url, self.injection_point
            )

            output = dumper.export_json(result, tmp_path)

            self.assertEqual(output, tmp_path)
            self.assertTrue(os.path.exists(tmp_path))

            with open(tmp_path, "r") as f:
                data = json.load(f)
                self.assertEqual(data["metadata"]["tables_dumped"], 1)
                self.assertEqual(
                    data["tables"]["SCHEMA1"]["TABLE1"][0]["COL1"], "value1"
                )

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    @patch("app.modules.scanner.database_dumper.OracleSchemaEnumerator")
    @patch("app.modules.scanner.database_dumper.OracleDataExtractor")
    def test_export_csv(self, mock_data_extractor, mock_schema_enumerator):
        """Test CSV export."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            result = DatabaseDumpResult(
                success=True, schemas_dumped=1, tables_dumped=1, rows_dumped=1
            )
            result.add_table_data("SCHEMA1", "TABLE1", [{"COL1": "value1"}])

            dumper = OracleDatabaseDumper(
                self.session, self.base_url, self.injection_point
            )

            outputs = dumper.export_csv(result, tmp_dir)

            self.assertEqual(len(outputs), 1)
            self.assertTrue(os.path.exists(outputs[0]))

            with open(outputs[0], "r") as f:
                reader = csv.reader(f)
                rows = list(reader)
                self.assertEqual(rows[0][0], "COL1")
                self.assertEqual(rows[1][0], "value1")

    @patch("app.modules.scanner.database_dumper.OracleSchemaEnumerator")
    @patch("app.modules.scanner.database_dumper.OracleDataExtractor")
    def test_export_sqlite(self, mock_data_extractor, mock_schema_enumerator):
        """Test SQLite export."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = DatabaseDumpResult(
                success=True, schemas_dumped=1, tables_dumped=1, rows_dumped=1
            )
            result.add_table_data("SCHEMA1", "TABLE1", [{"COL1": "value1"}])

            dumper = OracleDatabaseDumper(
                self.session, self.base_url, self.injection_point
            )

            output = dumper.export_sqlite(result, tmp_path)

            self.assertEqual(output, tmp_path)
            self.assertTrue(os.path.exists(tmp_path))

            conn = sqlite3.connect(tmp_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM SCHEMA1_TABLE1")
            row = cursor.fetchone()
            self.assertEqual(row[0], "value1")
            conn.close()

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    @patch("app.modules.scanner.database_dumper.OracleSchemaEnumerator")
    @patch("app.modules.scanner.database_dumper.OracleDataExtractor")
    def test_export_markdown(self, mock_data_extractor, mock_schema_enumerator):
        """Test Markdown export."""
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = DatabaseDumpResult(
                success=True, schemas_dumped=1, tables_dumped=1, rows_dumped=2
            )
            result.add_table_data(
                "SCHEMA1", "TABLE1", [{"COL1": "value1", "COL2": "value2"}]
            )

            dumper = OracleDatabaseDumper(
                self.session, self.base_url, self.injection_point
            )

            output = dumper.export_markdown(result, tmp_path)

            self.assertEqual(output, tmp_path)
            self.assertTrue(os.path.exists(tmp_path))

            with open(tmp_path, "r") as f:
                content = f.read()
                self.assertIn("Database Dump Report", content)
                self.assertIn("SCHEMA1", content)
                self.assertIn("TABLE1", content)
                self.assertIn("value1", content)

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    @patch("app.modules.scanner.database_dumper.OracleSchemaEnumerator")
    def test_estimate_remaining_time(self, mock_schema_enumerator):
        """Test estimating remaining time."""

        dumper = OracleDatabaseDumper(self.session, self.base_url, self.injection_point)

        dumper.current_progress["total_rows"] = 100
        dumper.current_progress["dumped_rows"] = 50
        dumper.current_progress["elapsed_time"] = 10

        remaining = dumper.estimate_remaining_time()

        self.assertGreaterEqual(remaining, 0)


if __name__ == "__main__":
    unittest.main()
