"""
Bridge between Scanner module and AI Service.
"""

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, ClassVar, NoReturn

from app.modules.scanner.exceptions.ai_analysis_exceptions import (
    ScannerAIAnalysisError,
    ScannerAIConnectionError,
    ScannerAINotConfiguredError,
    ScannerAIParsingError,
)
from app.services.ai import (
    AIConnectionError,
    AIParsingError,
    AIService,
    AIServiceError,
    AnalysisType,
    ConfidenceLevel,
    ModelNotConfiguredError,
    ParsedResponse,
    ParseError,
    SeverityLevel,
)


class ScannerFinding:
    """
    Represents a finding from the scanner.

    Attributes:
        vulnerability_type: Type of vulnerability
        severity: Severity level (critical, high, medium, low)
        description: Description of the finding
        location: Location of the finding
        evidence: Evidence of the finding
        confidence: Confidence level (high, medium, low)
        details: Additional details
        timestamp: When the finding was discovered
    """

    __slots__ = (
        "confidence",
        "description",
        "details",
        "evidence",
        "location",
        "severity",
        "timestamp",
        "vulnerability_type",
    )

    def __init__(
        self,
        vulnerability_type: str,
        severity: str,
        description: str,
        location: str,
        evidence: str | None = None,
        confidence: str = "medium",
        details: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> None:
        self.vulnerability_type = vulnerability_type
        self.severity = severity
        self.description = description
        self.location = location
        self.evidence = evidence
        self.confidence = confidence
        self.details = details or {}
        self.timestamp = timestamp or datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "description": self.description,
            "location": self.location,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


class ScanContext:
    """
    Context information for a scan.

    Attributes:
        url: Target URL
        method: HTTP method
        headers: Request headers
        payload: Payload used
        evidence: Evidence of vulnerability
        status_code: Response status code
        response_body: Response body
        scanner_module: Scanner module
        timestamp: When the scan occurred
        additional_data: Additional context data
    """

    __slots__ = (
        "additional_data",
        "evidence",
        "headers",
        "method",
        "payload",
        "response_body",
        "scanner_module",
        "status_code",
        "timestamp",
        "url",
    )

    def __init__(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        payload: str | None = None,
        evidence: str | None = None,
        status_code: int | None = None,
        response_body: str | None = None,
        scanner_module: str | None = None,
        timestamp: datetime | None = None,
        additional_data: dict[str, Any] | None = None,
    ) -> None:
        self.url = url
        self.method = method
        self.headers = headers or {}
        self.payload = payload
        self.evidence = evidence
        self.status_code = status_code
        self.response_body = response_body
        self.scanner_module = scanner_module
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.additional_data = additional_data or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary."""
        return {
            "url": self.url,
            "method": self.method,
            "headers": self.headers,
            "payload": self.payload,
            "evidence": self.evidence,
            "status_code": self.status_code,
            "response_body": self.response_body[:1000] if self.response_body else None,
            "scanner_module": self.scanner_module,
            "timestamp": self.timestamp.isoformat(),
            "additional_data": self.additional_data,
        }


class AIAnalysisService:
    """
    Bridge between Scanner module and AI Service.

    This service converts scanner findings into AI analysis requests
    and returns parsed AI responses.
    """

    # Class-level constants for severity and confidence mapping
    _SEVERITY_MAP: ClassVar[dict[str, SeverityLevel]] = {
        "critical": SeverityLevel.CRITICAL,
        "high": SeverityLevel.HIGH,
        "medium": SeverityLevel.MEDIUM,
        "low": SeverityLevel.LOW,
        "info": SeverityLevel.INFO,
    }

    _CONFIDENCE_MAP: ClassVar[dict[str, ConfidenceLevel]] = {
        "high": ConfidenceLevel.HIGH,
        "medium": ConfidenceLevel.MEDIUM,
        "low": ConfidenceLevel.LOW,
    }

    def __init__(
        self,
        ai_service: AIService,
        logger: logging.Logger | None = None,
        enabled: bool = True,
        cache_analyses: bool = True,
    ) -> None:
        """
        Initialize the AI Analysis Service.

        Args:
            ai_service: AIService instance for AI operations
            logger: Optional logger instance
            enabled: Whether AI analysis is enabled
            cache_analyses: Whether to cache analysis results

        Raises:
            ValueError: If ai_service is None
        """
        if ai_service is None:
            raise ValueError("ai_service cannot be None")

        self._ai_service = ai_service
        self._logger = logger or self._setup_logger()
        self._enabled = enabled
        self._cache_analyses = cache_analyses
        self._lock = threading.RLock()
        self._analysis_cache: dict[str, ParsedResponse] = {}
        self._processed_findings: set[str] = set()

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("AIAnalysisService")
        logger.setLevel(logging.DEBUG)
        if not logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            ch.setFormatter(formatter)
            logger.addHandler(ch)
        return logger

    def _get_cache_key(self, finding: ScannerFinding, context: ScanContext) -> str:
        """
        Generate a cache key for a finding.

        Args:
            finding: The scanner finding
            context: The scan context

        Returns:
            str: Cache key
        """
        return (
            f"{finding.vulnerability_type}:{finding.location}:"
            f"{finding.severity}:{finding.timestamp.timestamp()}"
        )

    def _is_analysis_required(
        self,
        finding: ScannerFinding,
        context: ScanContext,
    ) -> bool:
        """
        Check if analysis is required for a finding.

        Args:
            finding: The scanner finding
            context: The scan context

        Returns:
            bool: True if analysis is required
        """
        if not self._enabled:
            self._logger.debug("AI analysis is disabled")
            return False

        if not self._cache_analyses:
            return True

        cache_key = self._get_cache_key(finding, context)
        if cache_key in self._processed_findings:
            self._logger.debug(
                f"Skipping duplicate analysis for: {finding.vulnerability_type}"
            )
            return False

        return True

    def _prepare_scan_context(self, context: ScanContext) -> dict[str, Any]:
        """
        Prepare scan context for AI prompt.

        Args:
            context: Scan context

        Returns:
            dict[str, Any]: Prepared context dictionary
        """
        return {
            "url": context.url,
            "method": context.method,
            "headers": self._safe_json_dumps(context.headers),
            "payload": context.payload or "None",
            "evidence": context.evidence or "None",
            "status_code": context.status_code or "Unknown",
            "response_body": (
                context.response_body[:500] if context.response_body else "None"
            ),
            "scanner_module": context.scanner_module or "Unknown",
            "timestamp": context.timestamp.isoformat(),
            "additional_data": self._safe_json_dumps(context.additional_data, "None"),
        }

    @staticmethod
    def _safe_json_dumps(data: Any, default: str = "{}") -> str:
        """
        Safely convert data to JSON string.

        Args:
            data: Data to convert
            default: Default value if data is empty or conversion fails

        Returns:
            str: JSON string representation
        """
        if not data:
            return default
        try:
            return json.dumps(data, indent=2)
        except (TypeError, ValueError):
            return default

    def _severity_to_ai_level(self, severity: str) -> SeverityLevel:
        """
        Convert scanner severity to AI severity level.

        Args:
            severity: Scanner severity string

        Returns:
            SeverityLevel: AI severity level
        """
        return self._SEVERITY_MAP.get(severity.lower(), SeverityLevel.MEDIUM)

    def _confidence_to_ai_level(self, confidence: str) -> ConfidenceLevel:
        """
        Convert scanner confidence to AI confidence level.

        Args:
            confidence: Scanner confidence string

        Returns:
            ConfidenceLevel: AI confidence level
        """
        return self._CONFIDENCE_MAP.get(confidence.lower(), ConfidenceLevel.MEDIUM)

    def _handle_ai_error(self, error: Exception, context: str) -> NoReturn:
        """
        Handle AI service errors and raise appropriate scanner exceptions.

        Args:
            error: The original exception
            context: Error context description

        Raises:
            ScannerAINotConfiguredError: If model not configured
            ScannerAIConnectionError: If connection fails
            ScannerAIParsingError: If parsing fails
            ScannerAIAnalysisError: For other AI errors
        """
        self._logger.error(
            f"AI analysis error in {context}: {type(error).__name__} - {error!s}"
        )

        error_details: dict[str, Any] = {
            "context": context,
            "error_type": type(error).__name__,
        }

        if isinstance(error, ModelNotConfiguredError):
            raise ScannerAINotConfiguredError(
                f"AI service not configured: {error.message}",
                details=error_details,
            ) from error

        if isinstance(error, AIConnectionError):
            raise ScannerAIConnectionError(
                f"Connection to AI service failed: {error.message}",
                details=error_details,
            ) from error

        if isinstance(error, (AIParsingError, ParseError)):
            raise ScannerAIParsingError(
                f"Failed to parse AI response: {error.message}",
                details=error_details,
            ) from error

        if isinstance(error, AIServiceError):
            raise ScannerAIAnalysisError(
                f"AI service error: {error.message}",
                details=error_details,
            ) from error

        raise ScannerAIAnalysisError(
            f"Unexpected error: {error!s}",
            details=error_details,
        ) from error

    def _create_empty_response(self, analysis_type: AnalysisType) -> ParsedResponse:
        """
        Create an empty parsed response.

        Args:
            analysis_type: Type of analysis

        Returns:
            ParsedResponse: Empty response
        """
        return ParsedResponse(
            analysis_type=analysis_type,
            raw_text="",
            cleaned_text="",
            findings=[],
            summary="No analysis performed - no findings provided",
            confidence=ConfidenceLevel.UNKNOWN,
            is_json=False,
        )

    # =========================================================================
    # ANALYSIS METHODS
    # =========================================================================

    def analyze_sql_injection(
        self,
        finding: ScannerFinding,
        context: ScanContext,
    ) -> ParsedResponse:
        """Analyze SQL injection finding."""
        return self._analyze_finding(
            finding=finding,
            context=context,
            analysis_type=AnalysisType.SQL_INJECTION,
            method_name="generate_sql_analysis",
        )

    def analyze_xss(
        self,
        finding: ScannerFinding,
        context: ScanContext,
    ) -> ParsedResponse:
        """Analyze XSS finding."""
        return self._analyze_finding(
            finding=finding,
            context=context,
            analysis_type=AnalysisType.XSS,
            method_name="generate_xss_analysis",
        )

    def analyze_command_injection(
        self,
        finding: ScannerFinding,
        context: ScanContext,
    ) -> ParsedResponse:
        """Analyze command injection finding."""
        return self._analyze_finding(
            finding=finding,
            context=context,
            analysis_type=AnalysisType.GENERIC,
            method_name="generate_vulnerability_explanation",
            vulnerability_type="Command Injection",
        )

    def analyze_path_traversal(
        self,
        finding: ScannerFinding,
        context: ScanContext,
    ) -> ParsedResponse:
        """Analyze path traversal finding."""
        return self._analyze_finding(
            finding=finding,
            context=context,
            analysis_type=AnalysisType.GENERIC,
            method_name="generate_vulnerability_explanation",
            vulnerability_type="Path Traversal",
        )

    def analyze_ssrf(
        self,
        finding: ScannerFinding,
        context: ScanContext,
    ) -> ParsedResponse:
        """Analyze SSRF finding."""
        return self._analyze_finding(
            finding=finding,
            context=context,
            analysis_type=AnalysisType.GENERIC,
            method_name="generate_vulnerability_explanation",
            vulnerability_type="SSRF (Server-Side Request Forgery)",
        )

    def analyze_reverse_engineering(
        self,
        finding: ScannerFinding,
        context: ScanContext,
    ) -> ParsedResponse:
        """Analyze reverse engineering finding."""
        return self._analyze_finding(
            finding=finding,
            context=context,
            analysis_type=AnalysisType.REVERSE_ENGINEERING,
            method_name="generate_reverse_engineering",
            binary_info=finding.evidence or "No binary information provided",
        )

    def analyze_malware(
        self,
        finding: ScannerFinding,
        context: ScanContext,
    ) -> ParsedResponse:
        """Analyze malware finding."""
        return self._analyze_finding(
            finding=finding,
            context=context,
            analysis_type=AnalysisType.MALWARE_ANALYSIS,
            method_name="generate_malware_analysis",
            malware_info=finding.evidence or "No malware information provided",
        )

    def analyze_finding(
        self,
        scanner_name: str,
        finding: dict[str, Any],
        target: str = "",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Generic analysis wrapper.
        """
        scanner_finding = ScannerFinding(
            vulnerability_type=finding.get("vulnerability_type", "unknown"),
            severity=finding.get("severity", "medium"),
            description=finding.get("description", ""),
            location=finding.get("location", target),
            evidence=finding.get("evidence"),
            confidence=finding.get("confidence", "medium"),
            details=finding.get("details"),
        )
        scan_context = ScanContext(
            url=target,
            method=context.get("method", "GET") if context else "GET",
            headers=context.get("headers", {}) if context else {},
            payload=context.get("payload") if context else None,
            evidence=context.get("evidence") if context else None,
            status_code=context.get("status_code") if context else None,
            response_body=context.get("response_body") if context else None,
            scanner_module=scanner_name,
            additional_data=context.get("additional_data", {}) if context else {},
        )

        scanner_name = scanner_name.lower()
        if "xss" in scanner_name:
            return self.analyze_xss(scanner_finding, scan_context).to_dict()
        if "sql" in scanner_name:
            return self.analyze_sql_injection(scanner_finding, scan_context).to_dict()
        if "ssrf" in scanner_name:
            return self.analyze_ssrf(scanner_finding, scan_context).to_dict()

        if "path" in scanner_name:
            return self.analyze_path_traversal(scanner_finding, scan_context).to_dict()
        return {
            "severity": "medium",
            "confidence": 50,
            "analysis": "Generic AI analysis",
        }

    def generate_security_report(
        self,
        findings: list[ScannerFinding],
        context: ScanContext,
    ) -> ParsedResponse:
        """Generate a security report for multiple findings."""
        self._logger.info(f"Generating security report for {len(findings)} findings")

        if not findings:
            self._logger.info("No findings provided, returning empty response")
            return self._create_empty_response(AnalysisType.SECURITY_REPORT)

        if not self._is_analysis_required(findings[0], context):
            self._logger.info("Analysis not required (disabled or duplicate)")
            return self._create_empty_response(AnalysisType.SECURITY_REPORT)

        try:
            report_data = self._prepare_security_report_data(findings, context)
            result = self._ai_service.generate_security_report(
                report_data=report_data,
                context=context.url,
                additional_analysis=f"Found {len(findings)} vulnerabilities",
            )

            if self._cache_analyses:
                for finding in findings:
                    cache_key = self._get_cache_key(finding, context)
                    self._processed_findings.add(cache_key)
                    self._analysis_cache[cache_key] = result

            return result

        except Exception as e:
            self._handle_ai_error(e, "security_report_generation")
            raise  # Unreachable due to _handle_ai_error raising

    def explain_vulnerability(
        self,
        finding: ScannerFinding,
        context: ScanContext,
    ) -> ParsedResponse:
        """Explain a vulnerability finding."""
        return self._analyze_finding(
            finding=finding,
            context=context,
            analysis_type=AnalysisType.VULNERABILITY_EXPLANATION,
            method_name="generate_vulnerability_explanation",
            vulnerability_type=finding.vulnerability_type.replace("_", " ").title(),
        )

    # =========================================================================
    # PRIVATE ANALYSIS METHOD
    # =========================================================================

    def _analyze_finding(
        self,
        finding: ScannerFinding,
        context: ScanContext,
        analysis_type: AnalysisType,
        method_name: str,
        **kwargs: Any,
    ) -> ParsedResponse:
        """
        Generic method to analyze a finding.

        Args:
            finding: Scanner finding
            context: Scan context
            analysis_type: Type of analysis
            method_name: Name of the AI service method to call
            **kwargs: Additional arguments for the AI service method

        Returns:
            ParsedResponse: AI analysis response

        Raises:
            ScannerAIAnalysisError: If analysis fails
        """
        self._logger.info(
            f"Analyzing {finding.vulnerability_type} at {finding.location}"
        )

        if not self._is_analysis_required(finding, context):
            self._logger.info("Analysis not required (disabled or duplicate)")
            return self._create_empty_response(analysis_type)

        try:
            scan_context = self._prepare_scan_context(context)
            method = getattr(self._ai_service, method_name)

            # Build common arguments
            common_args = {
                "context": json.dumps(scan_context, indent=2),
                "additional_analysis": f"Severity: {finding.severity}, Confidence: {finding.confidence}",
            }

            # Method-specific argument mapping
            method_args_map = {
                "generate_sql_analysis": {
                    "sql_query": finding.evidence or finding.description
                },
                "generate_xss_analysis": {
                    "code": finding.evidence or finding.description
                },
                "generate_vulnerability_explanation": {
                    "vulnerability": kwargs.get(
                        "vulnerability_type", finding.vulnerability_type
                    ),
                    "additional_analysis": (
                        f"Description: {finding.description}\n"
                        f"Severity: {finding.severity}"
                    ),
                },
                "generate_reverse_engineering": {
                    "binary_info": kwargs.get(
                        "binary_info", finding.evidence or finding.description
                    ),
                },
                "generate_malware_analysis": {
                    "malware_info": kwargs.get(
                        "malware_info", finding.evidence or finding.description
                    ),
                },
            }

            # Get method-specific arguments or use defaults
            method_args = method_args_map.get(method_name, {})
            method_args.update(common_args)

            # Call the method with the arguments
            result = method(**method_args)

            if self._cache_analyses:
                cache_key = self._get_cache_key(finding, context)
                self._processed_findings.add(cache_key)
                self._analysis_cache[cache_key] = result

            return result

        except Exception as e:
            self._handle_ai_error(e, f"{method_name} for {finding.vulnerability_type}")
            raise  # Unreachable due to _handle_ai_error raising

    def _prepare_security_report_data(
        self,
        findings: list[ScannerFinding],
        context: ScanContext,
    ) -> str:
        """
        Prepare security report data for AI.

        Args:
            findings: List of scanner findings
            context: Scan context

        Returns:
            str: Report data string
        """
        report_data = {
            "target": context.url,
            "scan_time": context.timestamp.isoformat(),
            "findings_count": len(findings),
            "findings": [
                {
                    "type": finding.vulnerability_type,
                    "severity": finding.severity,
                    "description": finding.description,
                    "location": finding.location,
                    "confidence": finding.confidence,
                    "evidence": finding.evidence,
                    "details": finding.details,
                }
                for finding in findings
            ],
        }
        return json.dumps(report_data, indent=2)

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def clear_cache(self) -> None:
        """Clear the analysis cache."""
        with self._lock:
            self._analysis_cache.clear()
            self._processed_findings.clear()
            self._logger.info("Analysis cache cleared")

    def get_cache_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            dict[str, Any]: Cache statistics
        """
        with self._lock:
            return {
                "cached_analyses": len(self._analysis_cache),
                "processed_findings": len(self._processed_findings),
                "cache_enabled": self._cache_analyses,
                "analysis_enabled": self._enabled,
            }

    def is_enabled(self) -> bool:
        """
        Check if AI analysis is enabled.

        Returns:
            bool: True if enabled
        """
        return self._enabled

    def set_enabled(self, enabled: bool) -> None:
        """
        Enable or disable AI analysis.

        Args:
            enabled: Whether to enable AI analysis
        """
        with self._lock:
            self._enabled = enabled
            self._logger.info(f"AI analysis {'enabled' if enabled else 'disabled'}")
