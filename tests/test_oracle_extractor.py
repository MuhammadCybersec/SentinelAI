# tests/test_oracle_extractor.py
"""
Unit tests for Oracle data extraction.
Phase 4: Oracle Data Extraction
"""

import logging
import os
import sys
import unittest
from unittest.mock import Mock, PropertyMock, patch

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.oracle_extractor import (
    OracleDataExtractor,
    OracleExtractionResult,
)

# ============================================================
# TEST CLASS 1: Extraction Result Tests
# ============================================================


class TestOracleExtractionResult(unittest.TestCase):
    """Test OracleExtractionResult data class."""

    def test_extraction_result_initialization(self):
        """Test extraction result initialization."""
        result = OracleExtractionResult()

        self.assertFalse(result.success)
        self.assertIsNone(result.schema)
        self.assertIsNone(result.table)
        self.assertEqual(result.columns, [])
        self.assertEqual(result.rows, [])
        self.assertEqual(result.row_count, 0)
        self.assertEqual(result.errors, [])

    def test_add_error(self):
        """Test adding errors."""
        result = OracleExtractionResult()
        result.add_error("Test error 1")
        result.add_error("Test error 2")

        self.assertEqual(len(result.errors), 2)
        self.assertEqual(result.errors[0], "Test error 1")

    def test_get_summary_success(self):
        """Test summary generation on success."""
        result = OracleExtractionResult(
            success=True,
            schema="SCHEMA1",
            table="TABLE1",
            columns=["COL1", "COL2"],
            row_count=10,
            total_rows=100,
            execution_time=1.5,
            batch_size=50,
        )

        summary = result.get_summary()
        self.assertIn("Table: SCHEMA1.TABLE1", summary)
        self.assertIn("Rows: 10", summary)
        self.assertIn("Total: 100", summary)
        self.assertIn("Columns: 2", summary)
        self.assertIn("Time: 1.50s", summary)

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = OracleExtractionResult(success=False)
        summary = result.get_summary()
        self.assertEqual(summary, "Extraction failed")

    def test_get_summary_with_errors(self):
        """Test summary generation with errors."""
        result = OracleExtractionResult(success=True)
        result.add_error("Error 1")
        result.add_error("Error 2")

        summary = result.get_summary()
        self.assertIn("Errors: 2", summary)

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = OracleExtractionResult(
            success=True, schema="SCHEMA1", table="TABLE1", row_count=10
        )

        data = result.to_dict()

        self.assertEqual(data["success"], True)
        self.assertEqual(data["schema"], "SCHEMA1")
        self.assertEqual(data["table"], "TABLE1")
        self.assertEqual(data["row_count"], 10)
        self.assertIn("summary", data)

    def test_get_rows_as_list(self):
        """Test getting rows as list of lists."""
        result = OracleExtractionResult(
            columns=["COL1", "COL2"],
            rows=[
                {"COL1": "value1", "COL2": "value2"},
                {"COL1": "value3", "COL2": "value4"},
            ],
        )

        rows_list = result.get_rows_as_list()
        self.assertEqual(rows_list, [["value1", "value2"], ["value3", "value4"]])

    def test_get_first_row(self):
        """Test getting first row."""
        result = OracleExtractionResult(
            rows=[
                {"COL1": "value1", "COL2": "value2"},
                {"COL1": "value3", "COL2": "value4"},
            ]
        )

        first_row = result.get_first_row()
        self.assertEqual(first_row, {"COL1": "value1", "COL2": "value2"})

        result.rows = []
        self.assertIsNone(result.get_first_row())

    def test_get_last_row(self):
        """Test getting last row."""
        result = OracleExtractionResult(
            rows=[
                {"COL1": "value1", "COL2": "value2"},
                {"COL1": "value3", "COL2": "value4"},
            ]
        )

        last_row = result.get_last_row()
        self.assertEqual(last_row, {"COL1": "value3", "COL2": "value4"})

        result.rows = []
        self.assertIsNone(result.get_last_row())

    def test_get_column_data(self):
        """Test getting column data."""
        result = OracleExtractionResult(
            rows=[
                {"COL1": "value1", "COL2": "value2"},
                {"COL1": "value3", "COL2": "value4"},
            ]
        )

        col_data = result.get_column_data("COL1")
        self.assertEqual(col_data, ["value1", "value3"])

        col_data = result.get_column_data("NONEXISTENT")
        self.assertEqual(col_data, [None, None])


# ============================================================
# TEST CLASS 2: Data Extractor Tests
# ============================================================


class TestOracleDataExtractor(unittest.TestCase):
    """Test Oracle data extractor."""

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

    @patch("app.modules.scanner.oracle_extractor.UnionSQLi")
    def test_count_rows(self, mock_union_sqli):
        """Test counting rows."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        count_response = self._create_mock_response("COUNT: 100")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": count_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        extractor = OracleDataExtractor(self.session, self.base_url)
        extractor.union_sqli = mock_instance

        count = extractor.count_rows(self.injection_point, "SCHEMA1", "TABLE1")
        self.assertEqual(count, 100)

    @patch("app.modules.scanner.oracle_extractor.UnionSQLi")
    def test_extract_rows(self, mock_union_sqli):
        """Test extracting rows."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        rows_response = self._create_mock_response("COL1: value1, COL2: value2")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": rows_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        extractor = OracleDataExtractor(self.session, self.base_url)
        extractor.union_sqli = mock_instance

        result = extractor.extract_rows(
            self.injection_point,
            "SCHEMA1",
            "TABLE1",
            columns=["COL1", "COL2"],
            limit=10,
        )

        self.assertTrue(result.success)
        self.assertGreaterEqual(result.row_count, 0)

    @patch("app.modules.scanner.oracle_extractor.UnionSQLi")
    def test_extract_first_row(self, mock_union_sqli):
        """Test extracting first row."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        row_response = self._create_mock_response("COL1: value1, COL2: value2")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": row_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        extractor = OracleDataExtractor(self.session, self.base_url)
        extractor.union_sqli = mock_instance

        row = extractor.extract_first_row(
            self.injection_point, "SCHEMA1", "TABLE1", columns=["COL1", "COL2"]
        )

        self.assertIsNotNone(row)

    @patch("app.modules.scanner.oracle_extractor.UnionSQLi")
    def test_extract_sample(self, mock_union_sqli):
        """Test extracting sample."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        sample_response = self._create_mock_response("COL1: value1, COL2: value2")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": sample_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        extractor = OracleDataExtractor(self.session, self.base_url)
        extractor.union_sqli = mock_instance

        result = extractor.extract_sample(
            self.injection_point,
            "SCHEMA1",
            "TABLE1",
            columns=["COL1", "COL2"],
            sample_percent=10,
        )

        self.assertTrue(result.success)

    @patch("app.modules.scanner.oracle_extractor.UnionSQLi")
    def test_extract_column(self, mock_union_sqli):
        """Test extracting a single column."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        col_response = self._create_mock_response(
            "COL1: value1, COL1: value2, COL1: value3"
        )

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": col_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        extractor = OracleDataExtractor(self.session, self.base_url)
        extractor.union_sqli = mock_instance

        values = extractor.extract_column(
            self.injection_point, "SCHEMA1", "TABLE1", "COL1"
        )

        self.assertIsInstance(values, list)

    @patch("app.modules.scanner.oracle_extractor.UnionSQLi")
    def test_extract_columns(self, mock_union_sqli):
        """Test extracting multiple columns."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        cols_response = self._create_mock_response("COL1: value1, COL2: value2")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": cols_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        extractor = OracleDataExtractor(self.session, self.base_url)
        extractor.union_sqli = mock_instance

        data = extractor.extract_columns(
            self.injection_point, "SCHEMA1", "TABLE1", ["COL1", "COL2"]
        )

        self.assertIn("COL1", data)
        self.assertIn("COL2", data)

    @patch("app.modules.scanner.oracle_extractor.UnionSQLi")
    def test_handle_empty_table(self, mock_union_sqli):
        """Test handling empty table."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        empty_response = self._create_mock_response("No rows found")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": empty_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        extractor = OracleDataExtractor(self.session, self.base_url)
        extractor.union_sqli = mock_instance

        result = extractor.extract_rows(self.injection_point, "SCHEMA1", "TABLE1")

        self.assertFalse(result.success)
        self.assertEqual(result.row_count, 0)

    @patch("app.modules.scanner.oracle_extractor.UnionSQLi")
    def test_handle_null_values(self, mock_union_sqli):
        """Test handling NULL values."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        null_response = self._create_mock_response("COL1: NULL, COL2: value2")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": null_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        extractor = OracleDataExtractor(self.session, self.base_url)
        extractor.union_sqli = mock_instance

        # Should not crash with NULL values
        result = extractor.extract_rows(
            self.injection_point, "SCHEMA1", "TABLE1", columns=["COL1", "COL2"]
        )

        self.assertTrue(result.success)

    @patch("app.modules.scanner.oracle_extractor.UnionSQLi")
    def test_handle_unicode(self, mock_union_sqli):
        """Test handling Unicode values."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        unicode_response = self._create_mock_response("COL1: Café, COL2: こんにちは")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": unicode_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        extractor = OracleDataExtractor(self.session, self.base_url)
        extractor.union_sqli = mock_instance

        # Should not crash with Unicode values
        result = extractor.extract_rows(
            self.injection_point, "SCHEMA1", "TABLE1", columns=["COL1", "COL2"]
        )

        self.assertTrue(result.success)

    @patch("app.modules.scanner.oracle_extractor.UnionSQLi")
    def test_batch_extraction(self, mock_union_sqli):
        """Test batch extraction."""
        mock_instance = Mock()
        baseline_response = self._create_mock_response("Baseline")
        batch_response = self._create_mock_response("COL1: value1, COL2: value2")

        mock_instance.get_baseline.return_value = baseline_response
        mock_instance.test_payload.return_value = {
            "success": True,
            "response": batch_response,
            "has_changed": True,
        }
        mock_union_sqli.return_value = mock_instance

        extractor = OracleDataExtractor(self.session, self.base_url)
        extractor.union_sqli = mock_instance

        result = extractor.extract_rows_batched(
            self.injection_point, "SCHEMA1", "TABLE1", batch_size=10, max_rows=25
        )

        # Should handle batched extraction
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
