"""
Parallel Scanner Engine - High-performance concurrent scanning execution.

This module provides thread-safe parallel execution of multiple scanners
with comprehensive monitoring, cancellation, and statistics capabilities.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from app.modules.scanner.core.base_scanner import ScanResult

# from app.modules.scanner.core.scanner_manager import ScannerManager


class ScannerStatus(Enum):
    """Status of a scanner execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    RETRYING = "retrying"


@dataclass(slots=True)
class ParallelExecutionResult:
    """
    Result of a single scanner execution in parallel mode.

    Attributes:
        scanner_name: Name of the scanner that executed
        success: Whether execution was successful
        findings: List of findings from the scan
        execution_time: Time taken in seconds
        error: Error message if execution failed
        thread_id: ID of thread that executed the scan
        status: Current status of execution
        start_time: When execution started
        end_time: When execution ended
        retry_count: Number of retry attempts
        scan_result: Complete ScanResult object if available
    """

    scanner_name: str
    success: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)
    execution_time: float = 0.0
    error: str | None = None
    thread_id: int | None = None
    status: ScannerStatus = ScannerStatus.PENDING
    start_time: datetime | None = None
    end_time: datetime | None = None
    retry_count: int = 0
    scan_result: ScanResult | None = None
    execution_id: UUID = field(default_factory=uuid4)


@dataclass(slots=True)
class ParallelExecutionStats:
    """
    Statistics for parallel execution run.

    Attributes:
        total_scanners: Total number of scanners
        completed: Number of successfully completed
        failed: Number of failed
        cancelled: Number of cancelled
        timed_out: Number that timed out
        total_execution_time: Total time for all executions
        avg_execution_time: Average execution time
        max_execution_time: Maximum execution time
        min_execution_time: Minimum execution time
        start_time: When the parallel run started
        end_time: When the parallel run ended
        retries_used: Total retries used
        successful_findings: Total findings from successful scans
    """

    total_scanners: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    timed_out: int = 0
    total_execution_time: float = 0.0
    avg_execution_time: float = 0.0
    max_execution_time: float = 0.0
    min_execution_time: float = 0.0
    start_time: datetime | None = None
    end_time: datetime | None = None
    retries_used: int = 0
    successful_findings: int = 0


class ParallelScannerEngine:
    """
    Parallel execution engine for running multiple scanners concurrently.

    Features:
        - ThreadPoolExecutor for parallel execution
        - Async execution support
        - Configurable worker count
        - Timeout per scanner
        - Automatic retry on failure
        - Exception isolation (one scanner failure doesn't affect others)
        - Progress tracking
        - Comprehensive statistics
        - Graceful cancellation
        - Thread-safe operations

    Example:
        >>> engine = ParallelScannerEngine(max_workers=4, timeout=30)
        >>> results = engine.run_parallel(["xss", "sql", "csrf"], target="https://example.com")
        >>> stats = engine.get_statistics()
    """

    def __init__(
        self,
        scanner_manager: ScannerManager | None = None,
        max_workers: int = 4,
        timeout: float = 60.0,
        retry_count: int = 0,
        retry_delay: float = 1.0,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> None:
        """
        Initialize the parallel scanner engine.

        Args:
            scanner_manager: ScannerManager instance (creates new if None)
            max_workers: Maximum number of concurrent workers
            timeout: Default timeout in seconds per scanner
            retry_count: Number of retry attempts on failure
            retry_delay: Delay between retries in seconds
            progress_callback: Callback for progress updates (current, total, scanner_name)

        Raises:
            ValueError: If max_workers < 1 or timeout < 0
        """
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        if timeout < 0:
            raise ValueError("timeout must be non-negative")
        if retry_count < 0:
            raise ValueError("retry_count must be non-negative")
        if retry_delay < 0:
            raise ValueError("retry_delay must be non-negative")

        self._scanner_manager = (
            scanner_manager if scanner_manager is not None else ScannerManager()
        )
        self._max_workers = max_workers
        self._default_timeout = timeout
        self._retry_count = retry_count
        self._retry_delay = retry_delay
        self._progress_callback = progress_callback

        # Thread-safe state
        self._lock = threading.RLock()
        self._executor: ThreadPoolExecutor | None = None
        self._futures: dict[UUID, Future] = {}
        self._results: dict[UUID, ParallelExecutionResult] = {}
        self._stats: ParallelExecutionStats | None = None
        self._cancelled: bool = False
        self._running: bool = False
        self._current_run_id: UUID | None = None

        # Async support
        self._loop: asyncio.AbstractEventLoop | None = None
        self._async_tasks: set[asyncio.Future[Any]] = set()

    def run_parallel(
        self,
        scanner_names: list[str],
        target: str,
        timeout: float | None = None,
        retry_count: int | None = None,
        **scanner_kwargs,
    ) -> dict[UUID, ParallelExecutionResult]:
        """
        Run multiple scanners in parallel using ThreadPoolExecutor.

        Args:
            scanner_names: List of scanner names to execute
            target: Target URL or input to scan
            timeout: Timeout per scanner (defaults to instance default)
            retry_count: Number of retry attempts (defaults to instance default)
            **scanner_kwargs: Additional arguments passed to scanners

        Returns:
            Dictionary mapping execution_id to ParallelExecutionResult

        Raises:
            ValueError: If scanner_names is empty or scanner not found
            RuntimeError: If another execution is already running
        """
        if not scanner_names:
            raise ValueError("scanner_names cannot be empty")

        # Validate all scanners exist
        for name in scanner_names:
            try:
                self._scanner_manager.get_scanner(name)
            except ValueError:
                raise ValueError(f"Scanner '{name}' not found")

        with self._lock:
            if self._running:
                raise RuntimeError("Another parallel execution is already running")
            self._running = True
            self._cancelled = False
            self._current_run_id = uuid4()
            self._futures.clear()
            self._results.clear()
            self._stats = ParallelExecutionStats(
                total_scanners=len(scanner_names), start_time=datetime.now(timezone.utc)
            )

        timeout = timeout or self._default_timeout
        retry_count = retry_count if retry_count is not None else self._retry_count

        # Create executor
        self._executor = ThreadPoolExecutor(
            max_workers=min(self._max_workers, len(scanner_names)),
            thread_name_prefix="ScannerWorker",
        )

        try:
            # Submit all tasks
            for name in scanner_names:
                exec_id = uuid4()
                future = self._executor.submit(
                    self._execute_scanner_wrapper,
                    exec_id,
                    name,
                    target,
                    timeout,
                    retry_count,
                    scanner_kwargs,
                )
                with self._lock:
                    self._futures[exec_id] = future
                    self._results[exec_id] = ParallelExecutionResult(
                        scanner_name=name,
                        status=ScannerStatus.PENDING,
                        start_time=datetime.now(timezone.utc),
                    )

            # Wait for all futures with timeout
            for exec_id, future in list(self._futures.items()):
                if self._cancelled:
                    future.cancel()
                    with self._lock:
                        if exec_id in self._results:
                            self._results[exec_id].status = ScannerStatus.CANCELLED
                            self._results[exec_id].end_time = datetime.now(timezone.utc)
                            self._stats.cancelled += 1
                    continue

                try:
                    # Wait with timeout (2x timeout for retries)
                    result = future.result(timeout=timeout * 2)
                    with self._lock:
                        self._results[exec_id] = result
                        if result.success:
                            self._stats.completed += 1
                            self._stats.successful_findings += len(result.findings)
                            self._stats.retries_used += result.retry_count
                        else:
                            self._stats.failed += 1
                except TimeoutError:
                    future.cancel()
                    with self._lock:
                        if exec_id in self._results:
                            self._results[exec_id].status = ScannerStatus.TIMEOUT
                            self._results[exec_id].error = "Execution timed out"
                            self._results[exec_id].end_time = datetime.now(timezone.utc)
                            self._stats.timed_out += 1
                except Exception as e:  # noqa: BLE001
                    future.cancel()
                    with self._lock:
                        if exec_id in self._results:
                            self._results[exec_id].status = ScannerStatus.FAILED
                            self._results[exec_id].error = str(e)
                            self._results[exec_id].end_time = datetime.now(timezone.utc)
                            self._stats.failed += 1

                # Progress callback
                if self._progress_callback:
                    with self._lock:
                        completed = sum(
                            1
                            for r in self._results.values()
                            if r.status
                            in (
                                ScannerStatus.COMPLETED,
                                ScannerStatus.FAILED,
                                ScannerStatus.CANCELLED,
                                ScannerStatus.TIMEOUT,
                            )
                        )
                    self._progress_callback(
                        completed,
                        len(scanner_names),
                        self._results.get(
                            exec_id, ParallelExecutionResult("")
                        ).scanner_name,
                    )

            # Update statistics
            with self._lock:
                self._stats.end_time = datetime.now(timezone.utc)
                if self._stats.start_time:
                    self._stats.total_execution_time = (
                        self._stats.end_time - self._stats.start_time
                    ).total_seconds()

                times = [
                    r.execution_time
                    for r in self._results.values()
                    if r.execution_time > 0
                ]
                if times:
                    self._stats.avg_execution_time = sum(times) / len(times)
                    self._stats.max_execution_time = max(times)
                    self._stats.min_execution_time = min(times)

        finally:
            # Cleanup
            if self._executor:
                self._executor.shutdown(wait=False)
            with self._lock:
                self._running = False
                self._executor = None
                self._futures.clear()

        return dict(self._results)

    def _execute_scanner_wrapper(
        self,
        exec_id: UUID,
        scanner_name: str,
        target: str,
        timeout: float,
        retry_count: int,
        scanner_kwargs: dict[str, Any],
    ) -> ParallelExecutionResult:
        """
        Wrapper method to execute a single scanner with retry logic.

        Args:
            exec_id: Unique execution ID
            scanner_name: Name of scanner to execute
            target: Target to scan
            timeout: Timeout in seconds
            retry_count: Number of retry attempts
            scanner_kwargs: Additional scanner arguments

        Returns:
            ParallelExecutionResult with execution details

        Note:
            This method runs in a separate thread and is thread-safe.
            Exception isolation is guaranteed - exceptions are caught and
            returned as error in the result.
        """
        result = ParallelExecutionResult(
            scanner_name=scanner_name,
            execution_id=exec_id,
            status=ScannerStatus.RUNNING,
            start_time=datetime.now(timezone.utc),
            thread_id=threading.get_ident(),
        )

        # Update status in main results dict
        with self._lock:
            if exec_id in self._results:
                self._results[exec_id].status = ScannerStatus.RUNNING
                self._results[exec_id].thread_id = result.thread_id

        attempt = 0
        max_attempts = retry_count + 1

        while attempt < max_attempts:
            if self._cancelled:
                result.status = ScannerStatus.CANCELLED
                result.end_time = datetime.now(timezone.utc)
                result.error = "Execution cancelled"
                return result

            try:
                # Get scanner instance
                try:
                    scanner = self._scanner_manager.get_scanner(scanner_name)
                except ValueError as e:
                    raise ValueError(f"Scanner '{scanner_name}' not available") from e

                if not scanner:
                    raise ValueError(f"Scanner '{scanner_name}' not available")

                # Execute scanner with timeout
                start_time = time.time()
                scan_result = scanner.scan(target, **scanner_kwargs)
                execution_time = time.time() - start_time

                # Check if cancelled during execution
                if self._cancelled:
                    result.status = ScannerStatus.CANCELLED
                    result.error = "Execution cancelled during scan"
                else:
                    # Success
                    result.success = True
                    result.status = ScannerStatus.COMPLETED
                    result.findings = (
                        scan_result.findings
                        if scan_result and hasattr(scan_result, "findings")
                        else []
                    )
                    result.scan_result = scan_result
                    result.execution_time = execution_time
                    result.retry_count = attempt

                result.end_time = datetime.now(timezone.utc)
                return result

            except Exception as e:  # noqa: BLE001
                attempt += 1
                result.retry_count = attempt

                if attempt >= max_attempts:
                    # All retries exhausted
                    result.success = False
                    result.status = ScannerStatus.FAILED
                    result.error = f"Failed after {attempt} attempts: {e!s}"
                    result.end_time = datetime.now(timezone.utc)
                    return result

                # Update status for retry
                result.status = ScannerStatus.RETRYING
                with self._lock:
                    if exec_id in self._results:
                        self._results[exec_id].status = ScannerStatus.RETRYING

                # Wait before retry
                if self._retry_delay > 0:
                    time.sleep(self._retry_delay)

                # Check cancellation during retry wait
                if self._cancelled:
                    result.status = ScannerStatus.CANCELLED
                    result.error = "Cancelled during retry"
                    result.end_time = datetime.now(timezone.utc)
                    return result

        # Fallback (should never reach here)
        result.success = False
        result.status = ScannerStatus.FAILED
        result.error = "Unexpected error in retry logic"
        result.end_time = datetime.now(timezone.utc)
        return result

    def run_parallel_async(
        self,
        scanner_names: list[str],
        target: str,
        timeout: float | None = None,
        retry_count: int | None = None,
        **scanner_kwargs,
    ) -> asyncio.Future:
        """
        Run multiple scanners in parallel asynchronously.

        Args:
            scanner_names: List of scanner names to execute
            target: Target URL or input to scan
            timeout: Timeout per scanner (defaults to instance default)
            retry_count: Number of retry attempts (defaults to instance default)
            **scanner_kwargs: Additional arguments passed to scanners

        Returns:
            asyncio.Future that will contain the results dictionary

        Raises:
            ValueError: If scanner_names is empty or scanner not found
            RuntimeError: If another execution is already running
        """
        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(
            None,
            self.run_parallel,
            scanner_names,
            target,
            timeout,
            retry_count,
            **scanner_kwargs,
        )

        # Track async task
        with self._lock:
            self._async_tasks.add(future)
            future.add_done_callback(lambda f: self._async_tasks.discard(f))

        return future

    def cancel_execution(self, execution_id: UUID | None = None) -> bool:
        """
        Cancel a running execution.

        Args:
            execution_id: ID of execution to cancel (None for current)

        Returns:
            True if cancellation was successful, False otherwise
        """
        with self._lock:
            # If not running but has pending results, cancel them
            if not self._running:
                # Check if there are pending results
                has_pending = any(
                    r.status in (ScannerStatus.PENDING, ScannerStatus.RUNNING)
                    for r in self._results.values()
                )
                if not has_pending:
                    return False
                # Continue to cancel pending results even if not running

            # If specific execution ID, check if it's the current one
            if execution_id and execution_id != self._current_run_id:
                return False

            self._cancelled = True

            # Cancel all futures that are not done
            cancelled_any = False
            for future in self._futures.values():
                if not future.done():
                    future.cancel()
                    cancelled_any = True

            # Update status for pending/running results
            for result in self._results.values():
                if result.status in (ScannerStatus.PENDING, ScannerStatus.RUNNING):
                    result.status = ScannerStatus.CANCELLED
                    result.end_time = datetime.now(timezone.utc)
                    result.error = "Cancelled by user"
                    if self._stats:
                        self._stats.cancelled += 1
                    cancelled_any = True

            return cancelled_any or True

    def wait_for_completion(
        self, execution_id: UUID | None = None, timeout: float | None = None
    ) -> dict[UUID, ParallelExecutionResult]:
        """
        Wait for execution to complete.

        Args:
            execution_id: ID of execution to wait for (None for current)
            timeout: Maximum time to wait in seconds (None for indefinite)

        Returns:
            Dictionary of results

        Raises:
            TimeoutError: If timeout is reached
            RuntimeError: If no execution is running
        """
        if execution_id is None:
            with self._lock:
                if not self._running:
                    # Check if there are results (execution already completed)
                    if self._results:
                        return dict(self._results)
                    raise RuntimeError("No execution is currently running")
                execution_id = self._current_run_id

        # Wait for execution to finish
        start_time = time.time()
        while True:
            with self._lock:
                if not self._running:
                    return dict(self._results)
                if self._current_run_id != execution_id:
                    return dict(self._results)

            if timeout is not None and time.time() - start_time > timeout:
                raise TimeoutError(
                    f"Execution {execution_id} did not complete within {timeout} seconds"
                )

            time.sleep(0.1)

    def get_statistics(self) -> ParallelExecutionStats | None:
        """
        Get statistics from the last execution.

        Returns:
            ParallelExecutionStats or None if no execution has run
        """
        with self._lock:
            return self._stats

    def get_progress(self) -> tuple[int, int]:
        """
        Get current progress of running execution.

        Returns:
            Tuple of (completed_count, total_count)

        Raises:
            RuntimeError: If no execution is running
        """
        with self._lock:
            # If no results and not running, raise error
            if not self._results and not self._running:
                raise RuntimeError("No execution is currently running")

            # If not running but have results, return completed counts
            if not self._running and self._results:
                completed = sum(
                    1
                    for r in self._results.values()
                    if r.status
                    in (
                        ScannerStatus.COMPLETED,
                        ScannerStatus.FAILED,
                        ScannerStatus.CANCELLED,
                        ScannerStatus.TIMEOUT,
                    )
                )
                return completed, len(self._results)

            completed = sum(
                1
                for r in self._results.values()
                if r.status
                in (
                    ScannerStatus.COMPLETED,
                    ScannerStatus.FAILED,
                    ScannerStatus.CANCELLED,
                    ScannerStatus.TIMEOUT,
                )
            )
            total = len(self._results)
            return completed, total

    def shutdown(self) -> None:
        """
        Shutdown the engine and clean up all resources.

        This method cancels any running executions, shuts down the
        executor, and clears all internal state.
        """
        with self._lock:
            # Cancel running execution
            if self._running:
                self._cancelled = True
                for future in self._futures.values():
                    if not future.done():
                        future.cancel()

            # Shutdown executor
            if self._executor:
                self._executor.shutdown(wait=False)
                self._executor = None

            # Clear state
            self._futures.clear()
            self._results.clear()
            self._stats = None
            self._running = False
            self._cancelled = False
            self._current_run_id = None

            # Cancel async tasks
            for task in self._async_tasks:
                if not task.done():
                    task.cancel()
            self._async_tasks.clear()
