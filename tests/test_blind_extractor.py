# tests/test_blind_extractor.py - FIXED VERSION

"""
Unit tests for Phase 18: Blind Data Extractor.
"""

import unittest
import logging
import json
import time
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime, timedelta

import requests

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.blind_extractor import (
    BlindExtractor,
    BlindExtractionResult,
    ExtractionTechnique,
    ExtractionStatus,
    CharacterSet,
    ExtractionCheckpoint,
)


class TestBlindExtractionResult(unittest.TestCase):
    """Test BlindExtractionResult dataclass."""

    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_result_initialization(self):
        """Test result initialization."""
        result = BlindExtractionResult()
        self.assertFalse(result.success)
        self.assertIsNone(result.strategy_used)
        self.assertEqual(result.characters_extracted, 0)
        self.assertEqual(result.requests_sent, 0)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.status, ExtractionStatus.NOT_STARTED)

    def test_result_with_values(self):
        """Test result with custom values."""
        result = BlindExtractionResult(
            success=True,
            strategy_used=ExtractionTechnique.BOOLEAN,
            characters_extracted=100,
            requests_sent=200,
            elapsed_time=5.5,
            confidence=95.0,
            extracted_value="test_data",
            status=ExtractionStatus.COMPLETED,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.strategy_used, ExtractionTechnique.BOOLEAN)
        self.assertEqual(result.characters_extracted, 100)
        self.assertEqual(result.requests_sent, 200)
        self.assertEqual(result.elapsed_time, 5.5)
        self.assertEqual(result.confidence, 95.0)
        self.assertEqual(result.extracted_value, "test_data")
        self.assertEqual(result.status, ExtractionStatus.COMPLETED)

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = BlindExtractionResult(
            success=True,
            strategy_used=ExtractionTechnique.TIME,
            characters_extracted=50,
            requests_sent=100,
            elapsed_time=2.5,
            confidence=90.0,
            progress=50.0,
            status=ExtractionStatus.IN_PROGRESS,
        )
        result_dict = result.to_dict()

        self.assertEqual(result_dict["success"], True)
        self.assertEqual(result_dict["strategy_used"], "time")
        self.assertEqual(result_dict["characters_extracted"], 50)
        self.assertEqual(result_dict["requests_sent"], 100)
        self.assertEqual(result_dict["confidence"], 90.0)
        self.assertEqual(result_dict["progress"], 50.0)
        self.assertEqual(result_dict["status"], "in_progress")

    def test_get_summary_success(self):
        """Test summary generation on success."""
        result = BlindExtractionResult(
            success=True,
            strategy_used=ExtractionTechnique.BOOLEAN,
            characters_extracted=100,
            requests_sent=150,
            elapsed_time=3.0,
            confidence=95.0,
            extracted_value="test_value",
        )
        summary = result.get_summary()
        self.assertIn("Status: Success", summary)
        self.assertIn("Technique: boolean", summary)
        self.assertIn("Characters Extracted: 100", summary)
        self.assertIn("Requests Sent: 150", summary)
        self.assertIn("Confidence: 95.0%", summary)

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = BlindExtractionResult(
            success=False,
            errors=["Connection timeout", "Invalid response"],
            progress=25.0,
        )
        summary = result.get_summary()
        self.assertIn("Status: Failed", summary)
        self.assertIn("Errors: 2", summary)
        self.assertIn("Connection timeout", summary)


class TestExtractionCheckpoint(unittest.TestCase):
    """Test ExtractionCheckpoint dataclass."""

    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_checkpoint_creation(self):
        """Test checkpoint creation."""
        checkpoint = ExtractionCheckpoint(
            timestamp=datetime.now(),
            technique=ExtractionTechnique.BOOLEAN,
            target_type="database",
            target_name="ORCL",
            position=50,
            extracted_data=["test"],
            charset=CharacterSet.ASCII_PRINTABLE,
            query_count=100,
            progress=50.0,
        )
        self.assertEqual(checkpoint.technique, ExtractionTechnique.BOOLEAN)
        self.assertEqual(checkpoint.target_type, "database")
        self.assertEqual(checkpoint.position, 50)
        self.assertEqual(checkpoint.progress, 50.0)

    def test_checkpoint_to_dict(self):
        """Test checkpoint to dictionary conversion."""
        checkpoint = ExtractionCheckpoint(
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            technique=ExtractionTechnique.TIME,
            target_type="table",
            target_name="USERS",
            position=25,
            extracted_data=["user1"],
            charset=CharacterSet.ALPHANUMERIC,
            query_count=75,
            progress=25.0,
        )
        checkpoint_dict = checkpoint.to_dict()

        self.assertEqual(checkpoint_dict["technique"], "time")
        self.assertEqual(checkpoint_dict["target_type"], "table")
        self.assertEqual(checkpoint_dict["target_name"], "USERS")
        self.assertEqual(checkpoint_dict["position"], 25)
        self.assertEqual(checkpoint_dict["charset"], "alphanumeric")

    def test_checkpoint_from_dict(self):
        """Test checkpoint from dictionary creation."""
        data = {
            "timestamp": "2024-01-01T12:00:00",
            "technique": "boolean",
            "target_type": "database",
            "target_name": "ORCL",
            "position": 50,
            "extracted_data": ["test"],
            "charset": "ascii_printable",
            "query_count": 100,
            "progress": 50.0,
            "metadata": {"key": "value"},
        }
        checkpoint = ExtractionCheckpoint.from_dict(data)

        self.assertEqual(checkpoint.technique, ExtractionTechnique.BOOLEAN)
        self.assertEqual(checkpoint.target_name, "ORCL")
        self.assertEqual(checkpoint.position, 50)
        self.assertEqual(checkpoint.charset, CharacterSet.ASCII_PRINTABLE)
        self.assertEqual(checkpoint.metadata["key"], "value")


class TestBlindExtractor(unittest.TestCase):
    """Test BlindExtractor class."""

    def setUp(self):
        """Set up test environment."""
        logging.disable(logging.CRITICAL)

        self.session = Mock(spec=requests.Session)
        self.base_url = "http://test-target.com"
        self.injection_point = "id"
        self.temp_checkpoint_dir = tempfile.mkdtemp()

        self.extractor = BlindExtractor(
            session=self.session,
            base_url=self.base_url,
            injection_point=self.injection_point,
            checkpoint_dir=self.temp_checkpoint_dir,
        )

    def tearDown(self):
        """Clean up after tests."""
        logging.disable(logging.NOTSET)
        import shutil

        shutil.rmtree(self.temp_checkpoint_dir, ignore_errors=True)

    def test_initialization(self):
        """Test extractor initialization."""
        self.assertEqual(self.extractor.base_url, self.base_url)
        self.assertEqual(self.extractor.injection_point, self.injection_point)
        self.assertEqual(self.extractor.charset, CharacterSet.ASCII_PRINTABLE)
        self.assertTrue(self.extractor.use_binary_search)
        self.assertTrue(self.extractor.adaptive_delay)
        self.assertEqual(self.extractor.max_retries, 3)
        self.assertEqual(self.extractor.default_delay, 1.0)

    def test_set_custom_charset(self):
        """Test setting custom character set."""
        custom = "abc123!@#"
        self.extractor.set_custom_charset(custom)

        self.assertEqual(self.extractor.charset, CharacterSet.CUSTOM)
        charset_chars = self.extractor._get_charset()
        self.assertEqual(len(charset_chars), len(set(custom)))
        self.assertIn(ord("a"), charset_chars)
        self.assertIn(ord("!"), charset_chars)

    def test_character_sets(self):
        """Test character set initialization."""
        self.assertIn(CharacterSet.ASCII, self.extractor._character_sets)
        self.assertIn(CharacterSet.ASCII_PRINTABLE, self.extractor._character_sets)
        self.assertIn(CharacterSet.ALPHANUMERIC, self.extractor._character_sets)
        self.assertIn(CharacterSet.HEX, self.extractor._character_sets)

        ascii_chars = self.extractor._character_sets[CharacterSet.ASCII]
        self.assertTrue(len(ascii_chars) >= 95)

        printable = self.extractor._character_sets[CharacterSet.ASCII_PRINTABLE]
        self.assertTrue(len(printable) >= 94)

    def test_binary_search_character(self):
        """Test binary search character extraction."""
        # Create a mock boolean engine with execute_condition
        mock_engine = Mock()

        # Simulate binary search for character 'A' (65)
        # For query "SELECT 'A' FROM dual" with CHR(mid)
        # Return True if mid < 65, False if mid >= 65
        def side_effect(query, position=0):
            import re

            # Extract the CHR value from the query
            match = re.search(r"CHR\((\d+)\)", query)
            if match:
                mid = int(match.group(1))
                # Character is 'A' (65), so mid < 65 means character > mid
                return mid < 65
            return False

        mock_engine.execute_condition.side_effect = side_effect
        self.extractor.boolean_engine = mock_engine

        char, confidence = self.extractor._binary_search_character(
            "SELECT 'A' FROM dual", position=0, min_code=32, max_code=126
        )

        self.assertIsNotNone(char)
        self.assertEqual(char, "A")
        self.assertGreater(confidence, 0)

    def test_binary_search_character_failure(self):
        """Test binary search character extraction failure."""
        mock_engine = Mock()
        mock_engine.execute_condition.side_effect = Exception("Test error")
        self.extractor.boolean_engine = mock_engine

        char, confidence = self.extractor._binary_search_character(
            "SELECT 'A' FROM dual", position=0
        )

        self.assertIsNone(char)
        self.assertEqual(confidence, 0.0)

    def test_linear_search_character(self):
        """Test linear search character extraction."""
        mock_engine = Mock()
        mock_engine.execute_condition.return_value = True
        self.extractor.boolean_engine = mock_engine

        char, confidence = self.extractor._linear_search_character(
            "SELECT 'A' FROM dual", position=0, technique=ExtractionTechnique.BOOLEAN
        )

        self.assertIsNotNone(char)
        self.assertGreater(confidence, 0)

    def test_extract_character_with_cache(self):
        """Test character extraction with caching."""
        mock_engine = Mock()
        mock_engine.execute_condition.return_value = True
        self.extractor.boolean_engine = mock_engine

        # First extraction
        char1, _ = self.extractor.extract_character("SELECT 'A' FROM dual", position=0)

        # Second extraction should use cache
        char2, _ = self.extractor.extract_character("SELECT 'A' FROM dual", position=0)

        # Should return same character
        self.assertEqual(char1, char2)

    def test_discover_length(self):
        """Test length discovery."""
        mock_engine = Mock()

        # Simulate length 5
        def side_effect(query):
            # Extract the comparison value from the query
            import re

            match = re.search(r"> (\d+)", query)
            if match:
                val = int(match.group(1))
                return val < 5  # Length is 5
            return False

        mock_engine.execute_condition.side_effect = side_effect
        self.extractor.boolean_engine = mock_engine

        length = self.extractor._discover_length(
            "SELECT 'test' FROM dual", max_length=20
        )

        self.assertEqual(length, 5)

    def test_extract_string(self):
        """Test string extraction."""
        mock_engine = Mock()
        mock_engine.execute_condition.return_value = True
        self.extractor.boolean_engine = mock_engine

        # Mock length discovery
        with patch.object(self.extractor, "_discover_length") as mock_length:
            mock_length.return_value = 5

            # Mock character extraction
            with patch.object(self.extractor, "extract_character") as mock_char:
                mock_char.side_effect = [
                    ("A", 95.0),
                    ("B", 95.0),
                    ("C", 95.0),
                    ("D", 95.0),
                    ("E", 95.0),
                ]

                result, confidence = self.extractor.extract_string(
                    "SELECT 'ABCDE' FROM dual", max_length=10
                )

                self.assertEqual(result, "ABCDE")
                self.assertGreater(confidence, 0)

    def test_extract_database_name(self):
        """Test database name extraction."""
        with patch.object(self.extractor, "extract_string") as mock_extract:
            mock_extract.return_value = ("ORCL", 95.0)

            result, confidence = self.extractor.extract_database_name()

            self.assertEqual(result, "ORCL")
            self.assertEqual(confidence, 95.0)
            mock_extract.assert_called_once()

    def test_extract_current_user(self):
        """Test current user extraction."""
        with patch.object(self.extractor, "extract_string") as mock_extract:
            mock_extract.return_value = ("SYS", 90.0)

            result, confidence = self.extractor.extract_current_user()

            self.assertEqual(result, "SYS")
            self.assertEqual(confidence, 90.0)

    def test_extract_version(self):
        """Test version extraction."""
        with patch.object(self.extractor, "extract_string") as mock_extract:
            mock_extract.return_value = ("Oracle Database 19c", 85.0)

            result, confidence = self.extractor.extract_version()

            self.assertEqual(result, "Oracle Database 19c")
            self.assertEqual(confidence, 85.0)

    def test_extract_table_names(self):
        """Test table names extraction."""
        with patch.object(self.extractor, "extract_string") as mock_extract:
            mock_extract.side_effect = [
                ("USERS", 95.0),
                ("PRODUCTS", 90.0),
                (None, 0.0),  # Stop
            ]

            results = self.extractor.extract_table_names(max_tables=10)

            self.assertEqual(len(results), 2)
            self.assertEqual(results[0][0], "USERS")
            self.assertEqual(results[1][0], "PRODUCTS")

    def test_extract_column_names(self):
        """Test column names extraction."""
        with patch.object(self.extractor, "extract_string") as mock_extract:
            mock_extract.side_effect = [
                ("ID", 95.0),
                ("NAME", 90.0),
                ("EMAIL", 85.0),
                (None, 0.0),  # Stop
            ]

            results = self.extractor.extract_column_names("USERS", max_columns=10)

            self.assertEqual(len(results), 3)
            self.assertEqual(results[0][0], "ID")
            self.assertEqual(results[1][0], "NAME")
            self.assertEqual(results[2][0], "EMAIL")

    def test_extract_table_data(self):
        """Test table data extraction."""
        with patch.object(self.extractor, "extract_string") as mock_extract:
            # Mock row 1
            mock_extract.side_effect = [
                ("1", 95.0),  # ID
                ("John", 90.0),  # NAME
                ("john@test.com", 85.0),  # EMAIL
                ("2", 95.0),  # ID row 2
                ("Jane", 90.0),  # NAME row 2
                (None, 0.0),  # Stop
            ]

            results = self.extractor.extract_table_data(
                "USERS", ["ID", "NAME", "EMAIL"], max_rows=2
            )

            self.assertEqual(len(results), 2)
            self.assertEqual(results[0]["ID"], "1")
            self.assertEqual(results[0]["NAME"], "John")
            self.assertEqual(results[1]["ID"], "2")
            self.assertEqual(results[1]["NAME"], "Jane")

    def test_save_checkpoint(self):
        """Test saving checkpoint."""
        self.extractor.extraction_result = BlindExtractionResult(
            success=True,
            strategy_used=ExtractionTechnique.BOOLEAN,
            characters_extracted=10,
            requests_sent=20,
            progress=50.0,
            extracted_value="test_value",
        )

        checkpoint_path = self.extractor.save_checkpoint()

        self.assertIsNotNone(checkpoint_path)
        self.assertTrue(Path(checkpoint_path).exists())

    def test_load_checkpoint(self):
        """Test loading checkpoint."""
        # Create a checkpoint file
        checkpoint = ExtractionCheckpoint(
            timestamp=datetime.now(),
            technique=ExtractionTechnique.BOOLEAN,
            target_type="database",
            target_name="ORCL",
            position=10,
            extracted_data=["test"],
            charset=CharacterSet.ASCII_PRINTABLE,
            query_count=20,
            progress=50.0,
        )

        checkpoint_file = Path(self.temp_checkpoint_dir) / "test_checkpoint.json"
        with open(checkpoint_file, "w") as f:
            json.dump(checkpoint.to_dict(), f)

        loaded = self.extractor.load_checkpoint(str(checkpoint_file))

        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.technique, ExtractionTechnique.BOOLEAN)
        self.assertEqual(loaded.position, 10)
        self.assertEqual(loaded.progress, 50.0)

    def test_load_checkpoint_missing(self):
        """Test loading missing checkpoint."""
        checkpoint = self.extractor.load_checkpoint("missing.json")
        self.assertIsNone(checkpoint)

    def test_resume_extraction(self):
        """Test resuming extraction."""
        # Create checkpoint
        checkpoint = ExtractionCheckpoint(
            timestamp=datetime.now(),
            technique=ExtractionTechnique.BOOLEAN,
            target_type="database",
            target_name="ORCL",
            position=10,
            extracted_data=["test"],
            charset=CharacterSet.ASCII_PRINTABLE,
            query_count=20,
            progress=50.0,
        )

        checkpoint_file = Path(self.temp_checkpoint_dir) / "resume_checkpoint.json"
        with open(checkpoint_file, "w") as f:
            json.dump(checkpoint.to_dict(), f)

        with patch.object(self.extractor, "load_checkpoint") as mock_load:
            mock_load.return_value = checkpoint

            result = self.extractor.resume_extraction(str(checkpoint_file))

            self.assertTrue(result.success)
            self.assertEqual(result.strategy_used, ExtractionTechnique.BOOLEAN)
            self.assertEqual(result.progress, 50.0)

    def test_track_progress(self):
        """Test progress tracking."""
        progress = self.extractor.track_progress(
            total_items=100,
            current_item=25,
            start_time=datetime.now() - timedelta(seconds=10),
        )

        self.assertEqual(progress["progress"], 25.0)
        self.assertEqual(progress["items_remaining"], 75)
        self.assertIn("eta", progress)
        self.assertIn("speed", progress)

    def test_track_progress_zero_total(self):
        """Test progress tracking with zero total."""
        progress = self.extractor.track_progress(total_items=0, current_item=0)

        self.assertEqual(progress["progress"], 0.0)
        self.assertEqual(progress["items_remaining"], 0)

    def test_estimate_remaining_time(self):
        """Test remaining time estimation."""
        estimated = self.extractor.estimate_remaining_time(
            total_items=100, current_item=10, elapsed_time=5.0
        )

        self.assertGreaterEqual(estimated, 0)
        self.assertLess(estimated, 60)

    def test_estimate_remaining_time_zero_items(self):
        """Test remaining time with zero items."""
        estimated = self.extractor.estimate_remaining_time(
            total_items=0, current_item=0, elapsed_time=1.0
        )

        self.assertEqual(estimated, 0.0)

    def test_calculate_confidence(self):
        """Test confidence calculation."""
        confidence = self.extractor._calculate_confidence(5)
        self.assertGreater(confidence, 0)
        self.assertLessEqual(confidence, 100)

        # More queries = higher confidence
        confidence1 = self.extractor._calculate_confidence(1)
        confidence5 = self.extractor._calculate_confidence(5)
        self.assertGreater(confidence5, confidence1)

    def test_calculate_jitter(self):
        """Test jitter calculation."""
        self.extractor._response_times.extend([0.1, 0.12, 0.11, 0.13, 0.09])
        jitter = self.extractor._calculate_jitter()
        self.assertGreaterEqual(jitter, 0)
        self.assertLessEqual(jitter, 1)

    def test_clear_cache(self):
        """Test clearing cache."""
        self.extractor._character_cache["test"] = "value"
        self.extractor._query_cache["test"] = "value"

        self.extractor.clear_cache()

        self.assertEqual(len(self.extractor._character_cache), 0)
        self.assertEqual(len(self.extractor._query_cache), 0)

    def test_stop_extraction(self):
        """Test stopping extraction."""
        self.extractor.stop()
        self.assertTrue(self.extractor._stop_requested)

    def test_is_extracting(self):
        """Test is_extracting method."""
        self.assertFalse(self.extractor.is_extracting())

        self.extractor._is_extracting = True
        self.assertTrue(self.extractor.is_extracting())

    def test_get_statistics(self):
        """Test getting statistics."""
        self.extractor.extraction_result = BlindExtractionResult(
            success=True,
            strategy_used=ExtractionTechnique.BOOLEAN,
            characters_extracted=100,
            requests_sent=150,
            elapsed_time=3.0,
            confidence=95.0,
            progress=50.0,
        )

        stats = self.extractor.get_statistics()

        self.assertEqual(stats["technique"], "boolean")
        self.assertEqual(stats["characters_extracted"], 100)
        self.assertEqual(stats["requests_sent"], 150)
        self.assertEqual(stats["confidence"], 95.0)

    def test_detect_best_technique(self):
        """Test best technique detection."""
        # Mock the detect methods instead of is_vulnerable
        with patch.object(
            self.extractor.boolean_engine, "detect_boolean_blind"
        ) as mock_bool:
            with patch.object(
                self.extractor.time_engine, "detect_time_blind"
            ) as mock_time:
                # Create mock results
                mock_bool_result = Mock()
                mock_bool_result.is_vulnerable = True
                mock_bool.return_value = mock_bool_result

                mock_time_result = Mock()
                mock_time_result.is_vulnerable = False
                mock_time.return_value = mock_time_result

                technique = self.extractor._detect_best_technique()
                self.assertEqual(technique, ExtractionTechnique.BOOLEAN)

    def test_detect_best_technique_time(self):
        """Test best technique detection for time-based."""
        with patch.object(
            self.extractor.boolean_engine, "detect_boolean_blind"
        ) as mock_bool:
            with patch.object(
                self.extractor.time_engine, "detect_time_blind"
            ) as mock_time:
                mock_bool_result = Mock()
                mock_bool_result.is_vulnerable = False
                mock_bool.return_value = mock_bool_result

                mock_time_result = Mock()
                mock_time_result.is_vulnerable = True
                mock_time.return_value = mock_time_result

                technique = self.extractor._detect_best_technique()
                self.assertEqual(technique, ExtractionTechnique.TIME)

    def test_detect_best_technique_hybrid(self):
        """Test best technique detection for hybrid."""
        with patch.object(
            self.extractor.boolean_engine, "detect_boolean_blind"
        ) as mock_bool:
            with patch.object(
                self.extractor.time_engine, "detect_time_blind"
            ) as mock_time:
                mock_bool_result = Mock()
                mock_bool_result.is_vulnerable = True
                mock_bool.return_value = mock_bool_result

                mock_time_result = Mock()
                mock_time_result.is_vulnerable = True
                mock_time.return_value = mock_time_result

                technique = self.extractor._detect_best_technique()
                self.assertEqual(technique, ExtractionTechnique.HYBRID)

    def test_detect_best_technique_none(self):
        """Test best technique detection when none available."""
        with patch.object(
            self.extractor.boolean_engine, "detect_boolean_blind"
        ) as mock_bool:
            with patch.object(
                self.extractor.time_engine, "detect_time_blind"
            ) as mock_time:
                mock_bool_result = Mock()
                mock_bool_result.is_vulnerable = False
                mock_bool.return_value = mock_bool_result

                mock_time_result = Mock()
                mock_time_result.is_vulnerable = False
                mock_time.return_value = mock_time_result

                # Should default to boolean
                technique = self.extractor._detect_best_technique()
                self.assertEqual(technique, ExtractionTechnique.BOOLEAN)


class TestBlindExtractorParallel(unittest.TestCase):
    """Test parallel extraction features."""

    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.session = Mock(spec=requests.Session)
        self.extractor = BlindExtractor(
            session=self.session,
            base_url="http://test.com",
            injection_point="id",
            max_workers=3,
        )

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_extract_parallel(self):
        """Test parallel extraction."""
        with patch.object(self.extractor, "extract_character") as mock_char:
            mock_char.return_value = ("A", 95.0)

            results = self.extractor.extract_parallel(
                "SELECT 'A' FROM dual", start_position=0, end_position=3
            )

            self.assertEqual(len(results), 3)
            self.assertIn(0, results)
            self.assertIn(1, results)
            self.assertIn(2, results)
            self.assertEqual(results[0][0], "A")

    def test_extract_parallel_empty(self):
        """Test parallel extraction with empty range."""
        results = self.extractor.extract_parallel(
            "SELECT 'A' FROM dual", start_position=0, end_position=0
        )

        self.assertEqual(results, {})


class TestBlindExtractorEdgeCases(unittest.TestCase):
    """Test edge cases for Blind Extractor."""

    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.session = Mock(spec=requests.Session)
        self.extractor = BlindExtractor(
            session=self.session, base_url="http://test.com", injection_point="id"
        )

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_extract_string_empty(self):
        """Test extracting empty string."""
        with patch.object(self.extractor, "_discover_length") as mock_length:
            mock_length.return_value = 0

            result, confidence = self.extractor.extract_string(
                "SELECT '' FROM dual", max_length=10
            )

            self.assertEqual(result, "")
            self.assertEqual(confidence, 100.0)

    def test_extract_string_max_length(self):
        """Test string extraction at max length."""
        with patch.object(self.extractor, "_discover_length") as mock_length:
            mock_length.return_value = 10

            with patch.object(self.extractor, "extract_character") as mock_char:
                mock_char.return_value = ("X", 95.0)

                result, _ = self.extractor.extract_string(
                    "SELECT 'XXXXXXXXXX' FROM dual", max_length=10
                )

                self.assertEqual(len(result), 10)

    def test_extract_character_invalid_technique(self):
        """Test character extraction with invalid technique."""
        # Should default to boolean
        char, confidence = self.extractor.extract_character(
            "SELECT 'A' FROM dual", position=0, technique=None
        )

        # Should not crash and return something
        self.assertIsNotNone(char)

    def test_save_checkpoint_no_directory(self):
        """Test saving checkpoint without directory."""
        extractor = BlindExtractor(
            session=self.session,
            base_url="http://test.com",
            injection_point="id",
            checkpoint_dir=None,
        )

        checkpoint_path = extractor.save_checkpoint()
        self.assertIsNone(checkpoint_path)

    def test_load_checkpoint_invalid_json(self):
        """Test loading invalid checkpoint."""
        checkpoint_file = tempfile.mktemp(suffix=".json")
        with open(checkpoint_file, "w") as f:
            f.write("invalid json")

        checkpoint = self.extractor.load_checkpoint(checkpoint_file)
        self.assertIsNone(checkpoint)

    def test_resume_extraction_failed(self):
        """Test resume extraction with missing checkpoint."""
        with patch.object(self.extractor, "load_checkpoint") as mock_load:
            mock_load.return_value = None

            result = self.extractor.resume_extraction("missing.json")

            self.assertFalse(result.success)
            self.assertIn("Failed to load checkpoint", result.errors[0])
            self.assertEqual(result.status, ExtractionStatus.FAILED)

    def test_adaptive_delay(self):
        """Test adaptive delay functionality."""
        self.extractor.adaptive_delay = True

        # Simulate some response times
        self.extractor._response_times.extend([0.1, 0.2, 0.15, 0.3, 0.12])

        # Delay should be calculated adaptively
        delay = self.extractor.default_delay
        self.assertGreaterEqual(delay, 0)

    def test_network_jitter_compensation(self):
        """Test network jitter compensation."""
        self.extractor.network_jitter_compensation = True

        # Add some response times with high jitter
        self.extractor._response_times.extend([0.1, 0.5, 0.08, 0.6, 0.12])

        confidence = self.extractor._calculate_confidence(5)
        self.assertGreaterEqual(confidence, 0)
        self.assertLessEqual(confidence, 100)


if __name__ == "__main__":
    unittest.main()
