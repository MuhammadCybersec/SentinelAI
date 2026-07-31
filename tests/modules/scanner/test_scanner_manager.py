"""
Unit tests for ScannerManager.
"""

import pytest
import threading
import time
import logging
from unittest.mock import Mock, patch, MagicMock
from typing import List

from app.modules.scanner.core.scanner_manager import (
    ScannerManager,
    ScannerManagerError,
    ScannerNotFoundError,
    ScannerRegistrationError,
    ScannerExecutionError,
    ScannerInfo,
    ScannerExecutionResult,
)
from app.modules.scanner.core.base_scanner import BaseScanner, ScanResult, ScannerConfig

# ===========================================================
# Mock Scanner Classes
# ===========================================================


class MockXSSScanner(BaseScanner):
    """Mock XSS scanner for testing."""

    def __init__(self, target: str, **kwargs):
        super().__init__(target, config=ScannerConfig())
        self.version = "2.0.0"

    def run(self) -> List[ScanResult]:
        finding = self.create_finding(
            vulnerability_type="xss",
            severity="high",
            confidence=80.0,
            description="Mock XSS finding",
            url=self.target,
            parameter="q",
            payload="<script>alert('XSS')</script>",
        )
        return [finding]


class MockSQLiScanner(BaseScanner):
    """Mock SQL injection scanner for testing."""

    def __init__(self, target: str, **kwargs):
        super().__init__(target, config=ScannerConfig())
        self.version = "1.0.0"

    def run(self) -> List[ScanResult]:
        finding = self.create_finding(
            vulnerability_type="sql_injection",
            severity="critical",
            confidence=95.0,
            description="Mock SQL injection finding",
            url=self.target,
            parameter="id",
            payload="' OR '1'='1",
        )
        return [finding]


class MockFailingScanner(BaseScanner):
    """Mock failing scanner for testing."""

    def __init__(self, target: str, **kwargs):
        super().__init__(target, config=ScannerConfig())

    def run(self) -> List[ScanResult]:
        raise RuntimeError("Scanner failed intentionally")


# ===========================================================
# Test Fixtures
# ===========================================================


@pytest.fixture
def scanner_manager() -> ScannerManager:
    """Create a fresh ScannerManager instance."""
    return ScannerManager()


@pytest.fixture
def registered_manager(scanner_manager: ScannerManager) -> ScannerManager:
    """Register mock scanners."""
    scanner_manager.register(MockXSSScanner)
    scanner_manager.register(MockSQLiScanner)
    scanner_manager.register(MockFailingScanner, name="failing_scanner")
    return scanner_manager


# ===========================================================
# Tests
# ===========================================================


class TestScannerManager:
    """Tests for ScannerManager."""

    def test_initialization(self) -> None:
        """Test ScannerManager initialization."""
        manager = ScannerManager()
        assert len(manager) == 0
        assert isinstance(manager._logger, logging.Logger)

    def test_initialization_with_logger(self) -> None:
        """Test ScannerManager with custom logger."""
        logger = logging.getLogger("test_logger")
        manager = ScannerManager(logger=logger)
        assert manager._logger == logger

    def test_register_scanner(self, scanner_manager: ScannerManager) -> None:
        """Test registering a scanner."""
        scanner_manager.register(MockXSSScanner)
        assert len(scanner_manager) == 1
        assert "MockXSSScanner" in scanner_manager

    def test_register_scanner_with_custom_name(
        self, scanner_manager: ScannerManager
    ) -> None:
        """Test registering a scanner with custom name."""
        scanner_manager.register(MockXSSScanner, name="custom_xss")
        assert "custom_xss" in scanner_manager
        info = scanner_manager.get_scanner("custom_xss")
        assert info is not None
        assert info.name == "custom_xss"
        assert info.scanner_class == MockXSSScanner

    def test_register_scanner_with_description(
        self, scanner_manager: ScannerManager
    ) -> None:
        """Test registering a scanner with description."""
        scanner_manager.register(
            MockXSSScanner,
            name="xss",
            description="XSS vulnerability scanner",
            version="2.0.0",
            tags=["xss", "web"],
        )
        info = scanner_manager.get_scanner("xss")
        assert info is not None
        assert info.description == "XSS vulnerability scanner"
        assert info.version == "2.0.0"
        assert info.tags == ["xss", "web"]

    def test_register_duplicate_scanner(self, scanner_manager: ScannerManager) -> None:
        """Test registering a duplicate scanner raises error."""
        scanner_manager.register(MockXSSScanner)
        with pytest.raises(ScannerRegistrationError, match="already registered"):
            scanner_manager.register(MockXSSScanner)

    def test_register_invalid_scanner(self, scanner_manager: ScannerManager) -> None:
        """Test registering an invalid scanner raises error."""

        class InvalidScanner:
            pass

        with pytest.raises(ValueError, match="subclass of BaseScanner"):
            scanner_manager.register(InvalidScanner)  # type: ignore

    def test_unregister_scanner(self, scanner_manager: ScannerManager) -> None:
        """Test unregistering a scanner."""
        scanner_manager.register(MockXSSScanner)
        assert len(scanner_manager) == 1

        result = scanner_manager.unregister("MockXSSScanner")
        assert result is True
        assert len(scanner_manager) == 0

    def test_unregister_nonexistent_scanner(
        self, scanner_manager: ScannerManager
    ) -> None:
        """Test unregistering a non-existent scanner raises error."""
        with pytest.raises(ScannerNotFoundError, match="not found"):
            scanner_manager.unregister("nonexistent")

    def test_list_scanners(self, scanner_manager: ScannerManager) -> None:
        """Test listing all scanners."""
        scanner_manager.register(MockXSSScanner)
        scanner_manager.register(MockSQLiScanner)

        scanners = scanner_manager.list_scanners()
        assert len(scanners) == 2
        names = [s.name for s in scanners]
        assert "MockXSSScanner" in names
        assert "MockSQLiScanner" in names

    def test_get_scanner(self, scanner_manager: ScannerManager) -> None:
        """Test getting a scanner by name."""
        scanner_manager.register(MockXSSScanner)
        info = scanner_manager.get_scanner("MockXSSScanner")
        assert info is not None
        assert info.scanner_class == MockXSSScanner

    def test_get_scanner_not_found(self, scanner_manager: ScannerManager) -> None:
        """Test getting a non-existent scanner returns None."""
        info = scanner_manager.get_scanner("nonexistent")
        assert info is None

    def test_get_enabled_scanners(self, scanner_manager: ScannerManager) -> None:
        """Test getting enabled scanners."""
        scanner_manager.register(MockXSSScanner)
        scanner_manager.register(MockSQLiScanner, enabled=False)

        enabled = scanner_manager.get_enabled_scanners()
        assert len(enabled) == 1
        assert enabled[0].name == "MockXSSScanner"

    def test_enable_scanner(self, scanner_manager: ScannerManager) -> None:
        """Test enabling a scanner."""
        scanner_manager.register(MockXSSScanner, enabled=False)

        result = scanner_manager.enable_scanner("MockXSSScanner")
        assert result is True

        info = scanner_manager.get_scanner("MockXSSScanner")
        assert info is not None
        assert info.enabled is True

    def test_enable_nonexistent_scanner(self, scanner_manager: ScannerManager) -> None:
        """Test enabling a non-existent scanner raises error."""
        with pytest.raises(ScannerNotFoundError, match="not found"):
            scanner_manager.enable_scanner("nonexistent")

    def test_disable_scanner(self, scanner_manager: ScannerManager) -> None:
        """Test disabling a scanner."""
        scanner_manager.register(MockXSSScanner)

        result = scanner_manager.disable_scanner("MockXSSScanner")
        assert result is True

        info = scanner_manager.get_scanner("MockXSSScanner")
        assert info is not None
        assert info.enabled is False

    def test_disable_nonexistent_scanner(self, scanner_manager: ScannerManager) -> None:
        """Test disabling a non-existent scanner raises error."""
        with pytest.raises(ScannerNotFoundError, match="not found"):
            scanner_manager.disable_scanner("nonexistent")

    def test_contains_operator(self, scanner_manager: ScannerManager) -> None:
        """Test the `in` operator."""
        scanner_manager.register(MockXSSScanner)
        assert "MockXSSScanner" in scanner_manager
        assert "nonexistent" not in scanner_manager

    def test_len_operator(self, scanner_manager: ScannerManager) -> None:
        """Test the `len()` operator."""
        assert len(scanner_manager) == 0
        scanner_manager.register(MockXSSScanner)
        assert len(scanner_manager) == 1
        scanner_manager.register(MockSQLiScanner)
        assert len(scanner_manager) == 2

    def test_repr(self, scanner_manager: ScannerManager) -> None:
        """Test the `repr()` representation."""
        scanner_manager.register(MockXSSScanner)
        assert repr(scanner_manager) == "ScannerManager(scanners=1)"

    def test_clear(self, scanner_manager: ScannerManager) -> None:
        """Test clearing all scanners."""
        scanner_manager.register(MockXSSScanner)
        scanner_manager.register(MockSQLiScanner)
        assert len(scanner_manager) == 2

        scanner_manager.clear()
        assert len(scanner_manager) == 0


class TestScannerExecution:
    """Tests for scanner execution."""

    def test_run_scanner_success(self, registered_manager: ScannerManager) -> None:
        """Test running a scanner successfully."""
        result = registered_manager.run_scanner("MockXSSScanner", "https://example.com")

        assert result.success is True
        assert result.scanner_name == "MockXSSScanner"
        assert len(result.findings) == 1
        assert result.findings[0].vulnerability_type == "xss"
        assert result.error is None
        assert result.status == "completed"

    def test_run_scanner_not_found(self, registered_manager: ScannerManager) -> None:
        """Test running a non-existent scanner raises error."""
        with pytest.raises(ScannerNotFoundError, match="not found"):
            registered_manager.run_scanner("nonexistent", "https://example.com")

    def test_run_scanner_disabled(self, scanner_manager: ScannerManager) -> None:
        """Test running a disabled scanner."""
        scanner_manager.register(MockXSSScanner, enabled=False)

        result = scanner_manager.run_scanner("MockXSSScanner", "https://example.com")

        assert result.success is False
        assert result.error == "Scanner is disabled"
        assert result.status == "disabled"

    def test_run_scanner_failure(self, registered_manager: ScannerManager) -> None:
        """Test running a failing scanner."""
        result = registered_manager.run_scanner(
            "failing_scanner", "https://example.com"
        )

        assert result.success is False
        assert "failed intentionally" in result.error
        assert result.status == "failed"
        assert len(result.findings) == 0

    def test_run_all(self, registered_manager: ScannerManager) -> None:
        """Test running all enabled scanners."""
        # Disable failing scanner to avoid errors
        registered_manager.disable_scanner("failing_scanner")

        results = registered_manager.run_all("https://example.com")

        assert len(results) == 2  # MockXSSScanner and MockSQLiScanner
        assert all(r.success for r in results)
        assert sum(len(r.findings) for r in results) == 2

    def test_run_all_with_specific_scanners(
        self, registered_manager: ScannerManager
    ) -> None:
        """Test running specific scanners."""
        results = registered_manager.run_all(
            "https://example.com", scanner_names=["MockXSSScanner"]
        )

        assert len(results) == 1
        assert results[0].scanner_name == "MockXSSScanner"
        assert results[0].success is True

    def test_run_all_no_scanners(self, scanner_manager: ScannerManager) -> None:
        """Test running all when no scanners are registered."""
        results = scanner_manager.run_all("https://example.com")
        assert results == []

    def test_run_all_with_failures(self, registered_manager: ScannerManager) -> None:
        """Test running all scanners with some failures."""
        results = registered_manager.run_all("https://example.com")

        # Check that we got results for all 3 scanners
        assert len(results) == 3

        # Check which succeeded and which failed
        success_count = sum(1 for r in results if r.success)
        assert success_count == 2  # XSS and SQLi succeed

        # Check failing scanner
        failing_result = next(r for r in results if r.scanner_name == "failing_scanner")
        assert failing_result.success is False
        assert "failed intentionally" in failing_result.error


class TestParallelExecution:
    """Tests for parallel execution."""

    def test_run_all_async(self, registered_manager: ScannerManager) -> None:
        """Test running all scanners in parallel."""
        # Disable failing scanner to avoid errors
        registered_manager.disable_scanner("failing_scanner")

        results = registered_manager.run_all_async("https://example.com", max_workers=2)

        assert len(results) == 2
        assert all(r.success for r in results)
        assert sum(len(r.findings) for r in results) == 2

    def test_run_all_async_with_failures(
        self, registered_manager: ScannerManager
    ) -> None:
        """Test running all scanners in parallel with failures."""
        results = registered_manager.run_all_async("https://example.com", max_workers=2)

        assert len(results) == 3

        success_count = sum(1 for r in results if r.success)
        assert success_count == 2

    def test_run_all_async_no_scanners(self, scanner_manager: ScannerManager) -> None:
        """Test running all in parallel with no scanners."""
        results = scanner_manager.run_all_async("https://example.com")
        assert results == []

    def test_run_all_async_with_specific_scanners(
        self, registered_manager: ScannerManager
    ) -> None:
        """Test running specific scanners in parallel."""
        results = registered_manager.run_all_async(
            "https://example.com",
            scanner_names=["MockXSSScanner", "MockSQLiScanner"],
            max_workers=2,
        )

        assert len(results) == 2
        assert all(r.success for r in results)


class TestResultsSummary:
    """Tests for results summary."""

    def test_get_results_summary(self, registered_manager: ScannerManager) -> None:
        """Test getting a summary of results."""
        results = registered_manager.run_all("https://example.com")

        summary = registered_manager.get_results_summary(results)

        assert summary["total_scanners"] == 3
        assert summary["total_findings"] >= 1
        assert "severity_counts" in summary
        assert "results" in summary
        assert len(summary["results"]) == 3

    def test_get_results_summary_empty(
        self, registered_manager: ScannerManager
    ) -> None:
        """Test getting a summary of empty results."""
        summary = registered_manager.get_results_summary([])

        assert summary["total_scanners"] == 0
        assert summary["successful"] == 0
        assert summary["failed"] == 0
        assert summary["total_findings"] == 0
        assert summary["severity_counts"]["critical"] == 0


class TestStatistics:
    """Tests for statistics."""

    def test_get_statistics(self, registered_manager: ScannerManager) -> None:
        """Test getting manager statistics."""
        stats = registered_manager.get_statistics()

        assert stats["total_scanners"] == 3
        assert stats["enabled_scanners"] == 3  # All enabled by default
        assert stats["disabled_scanners"] == 0
        assert len(stats["scanners"]) == 3

    def test_get_statistics_with_disabled(
        self, scanner_manager: ScannerManager
    ) -> None:
        """Test statistics with disabled scanners."""
        scanner_manager.register(MockXSSScanner, enabled=True)
        scanner_manager.register(MockSQLiScanner, enabled=False)

        stats = scanner_manager.get_statistics()

        assert stats["total_scanners"] == 2
        assert stats["enabled_scanners"] == 1
        assert stats["disabled_scanners"] == 1


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_registration(self, scanner_manager: ScannerManager) -> None:
        """Test concurrent scanner registration."""

        def register_scanner(name: str) -> None:
            class DynamicScanner(BaseScanner):
                def run(self):
                    return []

            scanner_manager.register(DynamicScanner, name=name)

        threads = []
        for i in range(10):
            t = threading.Thread(target=register_scanner, args=(f"scanner_{i}",))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(scanner_manager) == 10

    def test_concurrent_run(self, registered_manager: ScannerManager) -> None:
        """Test concurrent scanner execution."""
        results: List[ScannerExecutionResult] = []
        errors: List[Exception] = []

        def run_scanner(name: str) -> None:
            try:
                result = registered_manager.run_scanner(name, "https://example.com")
                results.append(result)
            except Exception as e:
                errors.append(e)

        threads = []
        for name in ["MockXSSScanner", "MockSQLiScanner", "failing_scanner"]:
            t = threading.Thread(target=run_scanner, args=(name,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 3


class TestScannerInfo:
    """Tests for ScannerInfo dataclass."""

    def test_scanner_info_creation(self) -> None:
        """Test creating ScannerInfo."""
        info = ScannerInfo(
            name="test_scanner",
            scanner_class=MockXSSScanner,
            description="Test scanner",
            version="1.0.0",
            enabled=True,
            tags=["test", "web"],
        )

        assert info.name == "test_scanner"
        assert info.scanner_class == MockXSSScanner
        assert info.description == "Test scanner"
        assert info.version == "1.0.0"
        assert info.enabled is True
        assert info.tags == ["test", "web"]

    def test_scanner_info_to_dict(self) -> None:
        """Test converting ScannerInfo to dictionary."""
        info = ScannerInfo(
            name="test_scanner",
            scanner_class=MockXSSScanner,
            description="Test scanner",
            version="1.0.0",
            enabled=True,
            tags=["test"],
        )

        data = info.to_dict()
        assert data["name"] == "test_scanner"
        assert data["description"] == "Test scanner"
        assert data["version"] == "1.0.0"
        assert data["enabled"] is True
        assert data["tags"] == ["test"]


class TestScannerExecutionResult:
    """Tests for ScannerExecutionResult dataclass."""

    def test_execution_result_success(self) -> None:
        """Test successful execution result."""
        result = ScannerExecutionResult(
            scanner_name="test",
            success=True,
            findings=[],
            execution_time=1.5,
            status="completed",
        )

        assert result.scanner_name == "test"
        assert result.success is True
        assert result.findings == []
        assert result.execution_time == 1.5
        assert result.status == "completed"
        assert result.error is None

    def test_execution_result_failure(self) -> None:
        """Test failed execution result."""
        result = ScannerExecutionResult(
            scanner_name="test",
            success=False,
            findings=[],
            error="Test error",
            status="failed",
        )

        assert result.success is False
        assert result.error == "Test error"
        assert result.status == "failed"

    def test_execution_result_to_dict(self) -> None:
        """Test converting execution result to dictionary."""
        # Create a finding
        finding = ScanResult(
            scanner_name="test_scanner",
            vulnerability_type="xss",
            severity="high",
            confidence=80.0,
            url="https://example.com",
        )

        result = ScannerExecutionResult(
            scanner_name="test",
            success=True,
            findings=[finding],
            execution_time=1.5,
            status="completed",
        )

        data = result.to_dict()
        assert data["scanner_name"] == "test"
        assert data["success"] is True
        assert len(data["findings"]) == 1
        assert data["findings"][0]["vulnerability_type"] == "xss"
        assert data["execution_time"] == 1.5
        assert data["status"] == "completed"
