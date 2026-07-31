"""
===========================================================
Project : Sentinel AI
Module  : Scanner Manager
File ID : SCANNER-CORE-MANAGER-001
Version : 2.0.0
===========================================================

Description:

Centralized manager for all vulnerability scanners.

Provides:
- Scanner registration
- Scanner removal
- Scanner listing
- Single scanner execution
- Bulk scanner execution
- Thread safety
- Comprehensive logging
- Error handling

===========================================================
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Type

from app.modules.scanner.core.base_scanner import BaseScanner, ScanResult


class ScannerManagerError(Exception):
    """
    Base exception for ScannerManager errors.

    Attributes:
        message: Error message
        scanner_name: Name of the scanner (if applicable)
    """

    __slots__ = ("message", "scanner_name")

    def __init__(self, message: str, scanner_name: Optional[str] = None) -> None:
        self.message = message
        self.scanner_name = scanner_name
        super().__init__(message)


class ScannerNotFoundError(ScannerManagerError):
    """Raised when a scanner is not found."""

    pass


class ScannerRegistrationError(ScannerManagerError):
    """Raised when scanner registration fails."""

    pass


class ScannerExecutionError(ScannerManagerError):
    """Raised when scanner execution fails."""

    pass


@dataclass(slots=True)
class ScannerInfo:
    """
    Information about a registered scanner.

    Attributes:
        name: Scanner name
        scanner_class: The scanner class
        description: Scanner description
        version: Scanner version
        enabled: Whether the scanner is enabled
        tags: List of tags for categorization
    """

    name: str
    scanner_class: Type[BaseScanner]
    description: str = ""
    version: str = "1.0.0"
    enabled: bool = True
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "enabled": self.enabled,
            "tags": self.tags,
        }


@dataclass(slots=True)
class ScannerExecutionResult:
    """
    Result of a scanner execution.

    Attributes:
        scanner_name: Name of the scanner
        success: Whether execution was successful
        findings: List of findings
        error: Error message if failed
        execution_time: Time taken in seconds
        status: Status of execution
    """

    scanner_name: str
    success: bool
    findings: List[ScanResult]
    error: Optional[str] = None
    execution_time: float = 0.0
    status: str = "completed"

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert execution result to dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation
        """
        return {
            "scanner_name": self.scanner_name,
            "success": self.success,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "execution_time": self.execution_time,
            "status": self.status,
        }


class ScannerManager:
    """
    Centralized manager for all vulnerability scanners.

    This class manages the lifecycle of all scanners including
    registration, execution, and result aggregation.

    Features:
        - Thread-safe operations
        - Scanner registration and removal
        - Single and bulk execution
        - Comprehensive error handling
        - Detailed logging

    Example:
        >>> manager = ScannerManager()
        >>> manager.register(XSSScanner)
        >>> manager.register(SQLiScanner)
        >>> results = manager.run_all("https://example.com")
        >>> for result in results:
        ...     print(result.scanner_name, len(result.findings))
    """

    def __init__(
        self,
        logger: Optional[logging.Logger] = None,
        enable_auto_discovery: bool = False,
    ) -> None:
        """
        Initialize the ScannerManager.

        Args:
            logger: Optional logger instance
            enable_auto_discovery: Enable auto-discovery of scanners
        """
        self._logger = logger or self._setup_logger()
        self._scanners: Dict[str, ScannerInfo] = {}
        self._lock = threading.RLock()
        self._enable_auto_discovery = enable_auto_discovery

        self._logger.info("ScannerManager initialized")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("ScannerManager")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            ch.setFormatter(formatter)
            logger.addHandler(ch)
        return logger

    def register(
        self,
        scanner_class: Type[BaseScanner],
        name: Optional[str] = None,
        description: str = "",
        version: str = "1.0.0",
        enabled: bool = True,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Register a scanner with the manager.

        Args:
            scanner_class: The scanner class to register
            name: Optional custom name (defaults to class name)
            description: Scanner description
            version: Scanner version
            enabled: Whether the scanner is enabled
            tags: List of tags for categorization

        Raises:
            ScannerRegistrationError: If registration fails
            ValueError: If scanner_class is not a subclass of BaseScanner
        """
        if not issubclass(scanner_class, BaseScanner):
            raise ValueError(
                f"Scanner class must be a subclass of BaseScanner, got {scanner_class.__name__}"
            )

        scanner_name = name or scanner_class.__name__

        with self._lock:
            if scanner_name in self._scanners:
                raise ScannerRegistrationError(
                    f"Scanner '{scanner_name}' is already registered",
                    scanner_name=scanner_name,
                )

            # Create scanner info
            info = ScannerInfo(
                name=scanner_name,
                scanner_class=scanner_class,
                description=description or self._get_scanner_description(scanner_class),
                version=version,
                enabled=enabled,
                tags=tags or [],
            )

            self._scanners[scanner_name] = info
            self._logger.info(f"Registered scanner: {scanner_name} (v{version})")

    def unregister(self, scanner_name: str) -> bool:
        """
        Unregister a scanner from the manager.

        Args:
            scanner_name: Name of the scanner to unregister

        Returns:
            bool: True if removed, False if not found

        Raises:
            ScannerNotFoundError: If scanner is not found
        """
        with self._lock:
            if scanner_name not in self._scanners:
                raise ScannerNotFoundError(
                    f"Scanner '{scanner_name}' not found",
                    scanner_name=scanner_name,
                )

            removed = self._scanners.pop(scanner_name)
            self._logger.info(f"Unregistered scanner: {scanner_name}")
            return True

    def list_scanners(self) -> List[ScannerInfo]:
        """
        Get a list of all registered scanners.

        Returns:
            List[ScannerInfo]: List of scanner information
        """
        with self._lock:
            return list(self._scanners.values())

    def get_scanner(self, scanner_name: str) -> Optional[ScannerInfo]:
        """
        Get information about a specific scanner.

        Args:
            scanner_name: Name of the scanner

        Returns:
            Optional[ScannerInfo]: Scanner info or None if not found
        """
        with self._lock:
            return self._scanners.get(scanner_name)

    def get_enabled_scanners(self) -> list[ScannerInfo]:
        """
        Get a list of enabled scanners.

        Returns:
            List[ScannerInfo]: List of enabled scanner information
        """
        with self._lock:
            return [info for info in self._scanners.values() if info.enabled]

    def enable_scanner(self, scanner_name: str) -> bool:
        """
        Enable a scanner.

        Args:
            scanner_name: Name of the scanner to enable

        Returns:
            bool: True if enabled

        Raises:
            ScannerNotFoundError: If scanner is not found
        """
        with self._lock:
            if scanner_name not in self._scanners:
                raise ScannerNotFoundError(
                    f"Scanner '{scanner_name}' not found",
                    scanner_name=scanner_name,
                )

            self._scanners[scanner_name].enabled = True
            self._logger.info(f"Enabled scanner: {scanner_name}")
            return True

    def disable_scanner(self, scanner_name: str) -> bool:
        """
        Disable a scanner.

        Args:
            scanner_name: Name of the scanner to disable

        Returns:
            bool: True if disabled

        Raises:
            ScannerNotFoundError: If scanner is not found
        """
        with self._lock:
            if scanner_name not in self._scanners:
                raise ScannerNotFoundError(
                    f"Scanner '{scanner_name}' not found",
                    scanner_name=scanner_name,
                )

            self._scanners[scanner_name].enabled = False
            self._logger.info(f"Disabled scanner: {scanner_name}")
            return True

    def run_scanner(
        self,
        scanner_name: str,
        target: str,
        **kwargs: Any,
    ) -> ScannerExecutionResult:
        """
        Run a single scanner on a target.

        Args:
            scanner_name: Name of the scanner to run
            target: Target URL or identifier
            **kwargs: Additional arguments to pass to the scanner

        Returns:
            ScannerExecutionResult: Execution result

        Raises:
            ScannerNotFoundError: If scanner is not found
            ScannerExecutionError: If execution fails
        """
        import time

        with self._lock:
            info = self._scanners.get(scanner_name)
            if not info:
                raise ScannerNotFoundError(
                    f"Scanner '{scanner_name}' not found",
                    scanner_name=scanner_name,
                )

            if not info.enabled:
                self._logger.warning(f"Scanner '{scanner_name}' is disabled, skipping")
                return ScannerExecutionResult(
                    scanner_name=scanner_name,
                    success=False,
                    findings=[],
                    error="Scanner is disabled",
                    status="disabled",
                )

        self._logger.info(f"Running scanner: {scanner_name} on {target}")
        start_time = time.perf_counter()

        try:
            # Instantiate and run the scanner
            scanner = info.scanner_class(target, **kwargs)
            findings = scanner.run()

            execution_time = time.perf_counter() - start_time
            self._logger.info(
                f"Scanner '{scanner_name}' completed: {len(findings)} findings in {execution_time:.2f}s"
            )

            return ScannerExecutionResult(
                scanner_name=scanner_name,
                success=True,
                findings=findings,
                execution_time=execution_time,
                status="completed",
            )

        except Exception as e:
            execution_time = time.perf_counter() - start_time
            error_msg = f"Scanner '{scanner_name}' failed: {str(e)}"
            self._logger.error(error_msg)

            return ScannerExecutionResult(
                scanner_name=scanner_name,
                success=False,
                findings=[],
                error=str(e),
                execution_time=execution_time,
                status="failed",
            )

    def run_all(
        self,
        target: str,
        scanner_names: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> List[ScannerExecutionResult]:
        """
        Run all enabled scanners on a target.

        Args:
            target: Target URL or identifier
            scanner_names: Optional list of specific scanners to run
            **kwargs: Additional arguments to pass to scanners

        Returns:
            List[ScannerExecutionResult]: List of execution results
        """
        self._logger.info(f"Running scanners on {target}")

        if scanner_names:
            # Run specific scanners
            scanners_to_run = []
            with self._lock:
                for name in scanner_names:
                    info = self._scanners.get(name)
                    if info and info.enabled:
                        scanners_to_run.append(name)
        else:
            # Run all enabled scanners
            with self._lock:
                scanners_to_run = [
                    name for name, info in self._scanners.items() if info.enabled
                ]

        if not scanners_to_run:
            self._logger.warning("No enabled scanners found to run")
            return []

        self._logger.info(
            f"Running {len(scanners_to_run)} scanners: {', '.join(scanners_to_run)}"
        )

        results: List[ScannerExecutionResult] = []

        for scanner_name in scanners_to_run:
            result = self.run_scanner(scanner_name, target, **kwargs)
            results.append(result)

        # Summary
        successful = sum(1 for r in results if r.success)
        total_findings = sum(len(r.findings) for r in results)
        self._logger.info(
            f"Scan complete: {successful}/{len(results)} scanners succeeded, "
            f"{total_findings} total findings"
        )

        return results

    def run_all_async(
        self,
        target: str,
        scanner_names: Optional[List[str]] = None,
        max_workers: int = 4,
        **kwargs: Any,
    ) -> List[ScannerExecutionResult]:
        """
        Run all scanners in parallel using threads.

        Args:
            target: Target URL or identifier
            scanner_names: Optional list of specific scanners to run
            max_workers: Maximum concurrent scanners
            **kwargs: Additional arguments to pass to scanners

        Returns:
            List[ScannerExecutionResult]: List of execution results
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        self._logger.info(
            f"Running scanners in parallel on {target} (max_workers={max_workers})"
        )

        if scanner_names:
            with self._lock:
                scanners_to_run = [
                    (name, info)
                    for name, info in self._scanners.items()
                    if name in scanner_names and info.enabled
                ]
        else:
            with self._lock:
                scanners_to_run = [
                    (name, info)
                    for name, info in self._scanners.items()
                    if info.enabled
                ]

        if not scanners_to_run:
            self._logger.warning("No enabled scanners found to run")
            return []

        results: List[ScannerExecutionResult] = []
        errors: List[Exception] = []

        def run_scanner_task(name: str, info: ScannerInfo) -> ScannerExecutionResult:
            """Task to run a single scanner."""
            return self.run_scanner(name, target, **kwargs)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(run_scanner_task, name, info): name
                for name, info in scanners_to_run
            }

            for future in as_completed(futures):
                scanner_name = futures[future]
                try:
                    result = future.result(
                        timeout=60.0
                    )  # 60 second timeout per scanner
                    results.append(result)
                except Exception as e:
                    errors.append(e)
                    self._logger.error(
                        f"Scanner '{scanner_name}' failed with exception: {str(e)}"
                    )
                    results.append(
                        ScannerExecutionResult(
                            scanner_name=scanner_name,
                            success=False,
                            findings=[],
                            error=str(e),
                            status="failed",
                        )
                    )

        # Summary
        successful = sum(1 for r in results if r.success)
        total_findings = sum(len(r.findings) for r in results)
        self._logger.info(
            f"Parallel scan complete: {successful}/{len(results)} scanners succeeded, "
            f"{total_findings} total findings"
        )

        return results

    def get_results_summary(
        self, results: List[ScannerExecutionResult]
    ) -> Dict[str, Any]:
        """
        Get a summary of execution results.

        Args:
            results: List of ScannerExecutionResult

        Returns:
            Dict[str, Any]: Summary statistics
        """
        total = len(results)
        successful = sum(1 for r in results if r.success)
        failed = total - successful
        total_findings = sum(len(r.findings) for r in results)

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for result in results:
            for finding in result.findings:
                severity = finding.severity.lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

        return {
            "total_scanners": total,
            "successful": successful,
            "failed": failed,
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "results": [r.to_dict() for r in results],
        }

    def clear(self) -> None:
        """Clear all registered scanners."""
        with self._lock:
            self._scanners.clear()
            self._logger.info("Cleared all scanners")

    def _get_scanner_description(self, scanner_class: Type[BaseScanner]) -> str:
        """
        Get a description from a scanner class.

        Args:
            scanner_class: The scanner class

        Returns:
            str: Scanner description
        """
        docstring = scanner_class.__doc__
        if docstring:
            lines = docstring.strip().split("\n")
            if lines:
                return lines[0].strip()
        return scanner_class.__name__

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the manager.

        Returns:
            Dict[str, Any]: Manager statistics
        """
        with self._lock:
            enabled_count = sum(1 for info in self._scanners.values() if info.enabled)
            return {
                "total_scanners": len(self._scanners),
                "enabled_scanners": enabled_count,
                "disabled_scanners": len(self._scanners) - enabled_count,
                "scanners": [info.to_dict() for info in self._scanners.values()],
            }

    def __len__(self) -> int:
        """Return the number of registered scanners."""
        with self._lock:
            return len(self._scanners)

    def __contains__(self, scanner_name: str) -> bool:
        """Check if a scanner is registered."""
        with self._lock:
            return scanner_name in self._scanners

    def __repr__(self) -> str:
        """Return a string representation."""
        with self._lock:
            return f"ScannerManager(scanners={len(self._scanners)})"
