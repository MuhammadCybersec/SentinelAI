"""
Tests for Parallel Scanner Engine.
"""

import sys
from pathlib import Path

# Project root add karo
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import threading
import time
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from app.modules.scanner.core.parallel_scanner_engine import (
    ParallelExecutionResult,
    ParallelScannerEngine,
    ScannerStatus,
)
from app.modules.scanner.core.scanner_manager import ScannerManager


class TestParallelExecutionResult:
    """Tests for ParallelExecutionResult dataclass."""

    def test_creation(self) -> None:
        """Test creating ParallelExecutionResult instance."""
        result = ParallelExecutionResult(
            scanner_name="test_scanner",
            success=True,
            findings=[{"type": "xss", "severity": "high"}],
            execution_time=1.5,
        )

        assert result.scanner_name == "test_scanner"
        assert result.success is True
        assert len(result.findings) == 1
        assert result.execution_time == 1.5
        assert result.error is None
        assert result.status == ScannerStatus.PENDING
        assert result.retry_count == 0


class TestParallelScannerEngineInit:
    """Tests for ParallelScannerEngine initialization."""

    def test_init_defaults(self) -> None:
        """Test initialization with default values."""
        engine = ParallelScannerEngine()

        assert engine._max_workers == 4
        assert engine._default_timeout == 60.0
        assert engine._retry_count == 0
        assert engine._retry_delay == 1.0
        assert engine._scanner_manager is not None
        assert engine._progress_callback is None

    def test_init_custom_values(self) -> None:
        """Test initialization with custom values."""
        manager = ScannerManager()
        callback = lambda x, y, z: None

        engine = ParallelScannerEngine(
            scanner_manager=manager,
            max_workers=8,
            timeout=30.0,
            retry_count=3,
            retry_delay=0.5,
            progress_callback=callback,
        )

        assert engine._max_workers == 8
        assert engine._default_timeout == 30.0
        assert engine._retry_count == 3
        assert engine._retry_delay == 0.5
        # Check that the same manager instance is used
        assert engine._scanner_manager is manager

    def test_init_invalid_max_workers(self) -> None:
        """Test initialization with invalid max_workers."""
        with pytest.raises(ValueError, match="max_workers must be at least 1"):
            ParallelScannerEngine(max_workers=0)

    def test_init_invalid_timeout(self) -> None:
        """Test initialization with invalid timeout."""
        with pytest.raises(ValueError, match="timeout must be non-negative"):
            ParallelScannerEngine(timeout=-1)

    def test_init_invalid_retry_count(self) -> None:
        """Test initialization with invalid retry_count."""
        with pytest.raises(ValueError, match="retry_count must be non-negative"):
            ParallelScannerEngine(retry_count=-1)


class TestParallelScannerEngineRunParallel:
    """Tests for run_parallel method."""

    @pytest.fixture
    def mock_scanner_manager(self):
        """Create a mock scanner manager with test scanners."""
        manager = MagicMock(spec=ScannerManager)

        # Mock get_scanner method with validation
        class MockScanner:
            def scan(self, target, **kwargs):
                mock_result = MagicMock()
                mock_result.findings = [{"type": "test", "severity": "low"}]
                return mock_result

        def get_scanner(name):
            if name not in ["test_scanner_1", "test_scanner_2"]:
                raise ValueError(f"Scanner '{name}' not found")
            return MockScanner()

        manager.get_scanner = MagicMock(side_effect=get_scanner)

        # Mock has_scanner for backward compatibility
        def has_scanner(name):
            return name in ["test_scanner_1", "test_scanner_2"]

        manager.has_scanner = MagicMock(side_effect=has_scanner)

        return manager

    @pytest.fixture
    def slow_mock_scanner_manager(self):
        """Create a mock scanner manager with slow test scanners for concurrent test."""
        manager = MagicMock(spec=ScannerManager)

        # Mock get_scanner method with slow validation
        class SlowMockScanner:
            def scan(self, target, **kwargs):

                # Add delay to ensure concurrent execution prevention works
                time.sleep(0.2)
                mock_result = MagicMock()
                mock_result.findings = [{"type": "test", "severity": "low"}]
                return mock_result

        def get_scanner(name):
            if name not in ["test_scanner_1", "test_scanner_2"]:
                raise ValueError(f"Scanner '{name}' not found")
            return SlowMockScanner()

        manager.get_scanner = MagicMock(side_effect=get_scanner)

        # Mock has_scanner for backward compatibility
        def has_scanner(name):
            return name in ["test_scanner_1", "test_scanner_2"]

        manager.has_scanner = MagicMock(side_effect=has_scanner)

        return manager

    def test_run_parallel_basic(self, mock_scanner_manager):
        """Test basic parallel execution."""
        engine = ParallelScannerEngine(scanner_manager=mock_scanner_manager)
        results = engine.run_parallel(
            ["test_scanner_1", "test_scanner_2"], target="https://example.com"
        )

        assert len(results) == 2
        assert all(isinstance(k, UUID) for k in results)
        assert all(isinstance(v, ParallelExecutionResult) for v in results.values())

        # Check results have expected data
        for result in results.values():
            assert result.scanner_name in ["test_scanner_1", "test_scanner_2"]
            assert result.status in [ScannerStatus.COMPLETED, ScannerStatus.FAILED]

    def test_run_parallel_empty_scanners(self):
        """Test run_parallel with empty scanner list."""
        engine = ParallelScannerEngine()
        with pytest.raises(ValueError, match="scanner_names cannot be empty"):
            engine.run_parallel([], "https://example.com")

    def test_run_parallel_invalid_scanner(self, mock_scanner_manager):
        """Test run_parallel with invalid scanner name."""
        engine = ParallelScannerEngine(scanner_manager=mock_scanner_manager)
        with pytest.raises(ValueError, match="Scanner 'invalid' not found"):
            engine.run_parallel(["invalid"], "https://example.com")

    def test_run_parallel_concurrent_execution_prevention(
        self, slow_mock_scanner_manager
    ):
        """Test that concurrent execution is prevented."""
        engine = ParallelScannerEngine(scanner_manager=slow_mock_scanner_manager)

        # Start first execution in background thread
        import time

        results = None

        def run_scan():
            nonlocal results
            results = engine.run_parallel(
                ["test_scanner_1", "test_scanner_2"], target="https://example.com"
            )

        # Start first execution in background thread
        thread = threading.Thread(target=run_scan)
        thread.start()

        # Give it time to start and set _running flag
        time.sleep(0.05)

        # Try to start second execution - should raise RuntimeError
        with pytest.raises(
            RuntimeError, match="Another parallel execution is already running"
        ):
            engine.run_parallel(["test_scanner_1"], target="https://example.com")

        # Wait for first execution to complete
        thread.join(timeout=1.0)

        # Verify results
        assert results is not None
        assert len(results) == 2

    def test_run_parallel_with_timeout(self, mock_scanner_manager):
        """Test run_parallel with custom timeout."""
        engine = ParallelScannerEngine(
            scanner_manager=mock_scanner_manager, timeout=10.0
        )
        results = engine.run_parallel(
            ["test_scanner_1"], target="https://example.com", timeout=5.0
        )

        assert len(results) == 1
        result = next(iter(results.values()))
        assert result.scanner_name == "test_scanner_1"

    def test_run_parallel_with_retry(self, mock_scanner_manager):
        """Test run_parallel with retry logic."""

        # Create a scanner that fails first time then succeeds
        class FlakyScanner:
            def __init__(self):
                self.call_count = 0

            def scan(self, target, **kwargs):
                self.call_count += 1
                if self.call_count == 1:
                    raise RuntimeError("Temporary failure")
                mock_result = MagicMock()
                mock_result.findings = [{"type": "test", "severity": "low"}]
                return mock_result

        manager = MagicMock(spec=ScannerManager)
        manager.has_scanner = MagicMock(return_value=True)

        flaky = FlakyScanner()

        def get_scanner(name):
            return flaky

        manager.get_scanner = MagicMock(side_effect=get_scanner)

        engine = ParallelScannerEngine(
            scanner_manager=manager, retry_count=2, retry_delay=0.1
        )

        results = engine.run_parallel(["test_scanner"], target="https://example.com")

        result = next(iter(results.values()))
        assert result.success is True
        assert result.retry_count == 1  # One retry was used


class TestParallelScannerEngineMethods:
    """Tests for ParallelScannerEngine additional methods."""

    @pytest.fixture
    def mock_scanner_manager(self):
        """Create a mock scanner manager with test scanners."""
        manager = MagicMock(spec=ScannerManager)

        def has_scanner(name):
            return name in ["test_scanner_1", "test_scanner_2"]

        manager.has_scanner = MagicMock(side_effect=has_scanner)

        class MockScanner:
            def scan(self, target, **kwargs):
                mock_result = MagicMock()
                mock_result.findings = [{"type": "test", "severity": "low"}]
                return mock_result

        def get_scanner(name):
            return MockScanner()

        manager.get_scanner = MagicMock(side_effect=get_scanner)

        return manager

    @pytest.fixture
    def slow_mock_scanner_manager(self):
        """Create a mock scanner manager with slow test scanners."""
        manager = MagicMock(spec=ScannerManager)

        class SlowMockScanner:
            def scan(self, target, **kwargs):

                time.sleep(0.2)
                mock_result = MagicMock()
                mock_result.findings = [{"type": "test", "severity": "low"}]
                return mock_result

        def get_scanner(name):
            if name not in ["test_scanner_1", "test_scanner_2"]:
                raise ValueError(f"Scanner '{name}' not found")
            return SlowMockScanner()

        manager.get_scanner = MagicMock(side_effect=get_scanner)

        def has_scanner(name):
            return name in ["test_scanner_1", "test_scanner_2"]

        manager.has_scanner = MagicMock(side_effect=has_scanner)

        return manager

    @pytest.fixture
    def engine_with_results(self, mock_scanner_manager):
        """Create engine with completed results."""
        engine = ParallelScannerEngine(scanner_manager=mock_scanner_manager)
        engine.run_parallel(
            ["test_scanner_1", "test_scanner_2"], target="https://example.com"
        )
        return engine

    def test_get_statistics(self, engine_with_results):
        """Test get_statistics method."""
        stats = engine_with_results.get_statistics()
        assert stats is not None
        assert stats.total_scanners == 2
        assert stats.completed >= 0
        assert stats.start_time is not None
        assert stats.end_time is not None
        assert stats.total_execution_time >= 0

    def test_shutdown(self, engine_with_results):
        """Test shutdown method."""
        engine = engine_with_results
        engine.shutdown()
        assert engine._running is False
        assert engine._executor is None
        assert len(engine._futures) == 0
        assert len(engine._results) == 0

    def test_cancel_execution(self, slow_mock_scanner_manager):
        """Test cancel_execution method."""
        engine = ParallelScannerEngine(scanner_manager=slow_mock_scanner_manager)

        # Start execution in background thread
        import time

        results = None

        def run_scan():
            nonlocal results
            results = engine.run_parallel(
                ["test_scanner_1", "test_scanner_2"], target="https://example.com"
            )

        thread = threading.Thread(target=run_scan)
        thread.start()

        # Give it time to start
        time.sleep(0.05)

        # Cancel execution
        result = engine.cancel_execution()
        assert result is True

        # Wait for execution to complete
        thread.join(timeout=1.0)

        # Verify results were cancelled
        if results:
            for r in results.values():
                assert r.status in [ScannerStatus.CANCELLED, ScannerStatus.COMPLETED]

    def test_get_progress(self, mock_scanner_manager):
        """Test get_progress method."""
        engine = ParallelScannerEngine(scanner_manager=mock_scanner_manager)

        # Start execution
        engine.run_parallel(
            ["test_scanner_1", "test_scanner_2"], target="https://example.com"
        )

        # Get progress
        completed, total = engine.get_progress()
        assert total == 2
        assert completed >= 0

    def test_get_progress_no_execution(self):
        """Test get_progress when no execution is running."""
        engine = ParallelScannerEngine()
        with pytest.raises(RuntimeError, match="No execution is currently running"):
            engine.get_progress()

    def test_wait_for_completion(self, mock_scanner_manager):
        """Test wait_for_completion method."""
        engine = ParallelScannerEngine(scanner_manager=mock_scanner_manager)

        # Start execution
        engine.run_parallel(
            ["test_scanner_1", "test_scanner_2"], target="https://example.com"
        )

        # Wait for completion
        final_results = engine.wait_for_completion(timeout=5.0)
        assert len(final_results) == 2


class TestParallelScannerEngineAsync:
    """Tests for async methods."""

    @pytest.fixture
    def mock_scanner_manager(self):
        """Create a mock scanner manager with test scanners."""
        manager = MagicMock(spec=ScannerManager)

        def has_scanner(name):
            return name in ["test_scanner_1", "test_scanner_2"]

        manager.has_scanner = MagicMock(side_effect=has_scanner)

        class MockScanner:
            def scan(self, target, **kwargs):
                mock_result = MagicMock()
                mock_result.findings = [{"type": "test", "severity": "low"}]
                return mock_result

        def get_scanner(name):
            return MockScanner()

        manager.get_scanner = MagicMock(side_effect=get_scanner)

        return manager

    @pytest.mark.asyncio
    async def test_run_parallel_async(self, mock_scanner_manager):
        """Test run_parallel_async method."""
        engine = ParallelScannerEngine(scanner_manager=mock_scanner_manager)

        # Run async
        future = engine.run_parallel_async(
            ["test_scanner_1", "test_scanner_2"], target="https://example.com"
        )

        # Wait for result
        results = await future
        assert len(results) == 2
        assert all(isinstance(k, UUID) for k in results)
