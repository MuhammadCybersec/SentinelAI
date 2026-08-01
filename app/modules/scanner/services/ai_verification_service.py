"""
AI Auto Verification Service - Verify scanner findings using AI analysis.

This service provides AI-powered verification of security scanner findings
with confidence scoring, false-positive detection, risk analysis, and
standardized vulnerability assessment.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import typing
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from app.modules.scanner.services.ai_analysis_service import AIAnalysisService


class SeverityLevel(Enum):
    """Security severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


class VerificationStatus(Enum):
    """Status of a verification request."""

    PENDING = "pending"
    PROCESSING = "processing"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass(slots=True)
class CWEInfo:
    """
    CWE (Common Weakness Enumeration) information.

    Attributes:
        id: CWE ID (e.g., "CWE-79")
        name: CWE name
        description: CWE description
        severity: CWE severity
    """

    id: str
    name: str
    description: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM


@dataclass(slots=True)
class CVSSInfo:
    """
    CVSS (Common Vulnerability Scoring System) information.

    Attributes:
        score: CVSS score (0-10)
        vector: CVSS vector string
        severity: Severity level based on score
        metrics: Individual CVSS metrics
    """

    score: float = 0.0
    vector: str = ""
    severity: SeverityLevel = SeverityLevel.NONE
    metrics: dict[str, float] = field(default_factory=dict)


@dataclass(slots=True)
class VerificationResult:
    """
    Result of AI verification for a finding.

    Attributes:
        finding_id: Unique identifier for the finding
        scanner_name: Name of the scanner that found it
        verified: Whether finding is verified
        confidence: Confidence score (0-100)
        status: Verification status
        severity: Determined severity
        cvss: CVSS information
        cwe: CWE information
        false_positive: Whether determined as false positive
        false_positive_reason: Reason for false positive determination
        recommendations: Recommended actions
        explanation: AI explanation of verification
        verification_time: Time taken for verification
        metadata: Additional metadata
        created_at: When verification was created
    """

    finding_id: str
    scanner_name: str
    verified: bool = False
    confidence: float = 0.0
    status: VerificationStatus = VerificationStatus.PENDING
    severity: SeverityLevel = SeverityLevel.NONE
    cvss: CVSSInfo = field(default_factory=CVSSInfo)
    cwe: CWEInfo | None = None
    false_positive: bool = False
    false_positive_reason: str = ""
    recommendations: list[str] = field(default_factory=list)
    explanation: str = ""
    verification_time: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verification_id: UUID = field(default_factory=uuid4)


@dataclass(slots=True)
class VerificationContext:
    """
    Context for verification request.

    Attributes:
        target: Target being scanned
        finding_type: Type of finding
        finding_data: Original finding data
        context_data: Additional context data
        source_code: Source code if available
        request_data: HTTP request data
        response_data: HTTP response data
        environment: Environment information
    """

    target: str
    finding_type: str
    finding_data: dict[str, Any] = field(default_factory=dict)
    context_data: dict[str, Any] = field(default_factory=dict)
    source_code: str = ""
    request_data: dict[str, Any] = field(default_factory=dict)
    response_data: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class VerificationStats:
    """
    Statistics for verification batch.

    Attributes:
        total: Total findings verified
        verified: Successfully verified
        false_positives: False positives detected
        inconclusive: Inconclusive results
        errors: Errors encountered
        total_time: Total verification time
        avg_time: Average verification time
        avg_confidence: Average confidence score
        high_severity: High severity findings
        medium_severity: Medium severity findings
        low_severity: Low severity findings
        critical_severity: Critical severity findings
    """

    total: int = 0
    verified: int = 0
    false_positives: int = 0
    inconclusive: int = 0
    errors: int = 0
    total_time: float = 0.0
    avg_time: float = 0.0
    avg_confidence: float = 0.0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0
    critical_severity: int = 0


class VerificationConfig:
    """
    Configuration for AI verification service.

    Constants:
        MIN_CONFIDENCE_THRESHOLD: Minimum confidence for verification
        FALSE_POSITIVE_THRESHOLD: Threshold for false positive detection
        MAX_RETRIES: Maximum retry attempts
        RETRY_DELAY: Delay between retries
        TIMEOUT: Default timeout for verification
        MAX_BATCH_SIZE: Maximum batch size for batch verification
        CWE_MAPPINGS: CWE ID to info mapping
    """

    MIN_CONFIDENCE_THRESHOLD: float = 60.0
    FALSE_POSITIVE_THRESHOLD: float = 30.0
    MAX_RETRIES: int = 3
    RETRY_DELAY: float = 1.0
    TIMEOUT: float = 30.0
    MAX_BATCH_SIZE: int = 100

    # Common CWE mappings
    CWE_MAPPINGS: typing.ClassVar[dict[str, CWEInfo]] = {
        "CWE-79": CWEInfo(
            "CWE-79",
            "Cross-site Scripting (XSS)",
            "Improper Neutralization of Input During Web Page Generation",
            SeverityLevel.MEDIUM,
        ),
        "CWE-89": CWEInfo(
            "CWE-89",
            "SQL Injection",
            "Improper Neutralization of Special Elements used in an SQL Command",
            SeverityLevel.HIGH,
        ),
        "CWE-22": CWEInfo(
            "CWE-22",
            "Path Traversal",
            "Improper Limitation of a Pathname to a Restricted Directory",
            SeverityLevel.HIGH,
        ),
        "CWE-285": CWEInfo(
            "CWE-285",
            "Improper Authorization",
            "Improper Authorization",
            SeverityLevel.HIGH,
        ),
        "CWE-287": CWEInfo(
            "CWE-287",
            "Improper Authentication",
            "Improper Authentication",
            SeverityLevel.HIGH,
        ),
        "CWE-352": CWEInfo(
            "CWE-352",
            "Cross-Site Request Forgery (CSRF)",
            "Cross-Site Request Forgery",
            SeverityLevel.MEDIUM,
        ),
        "CWE-611": CWEInfo(
            "CWE-611",
            "XXE Injection",
            "Improper Restriction of XML External Entity Reference",
            SeverityLevel.HIGH,
        ),
        "CWE-918": CWEInfo(
            "CWE-918",
            "Server-Side Request Forgery (SSRF)",
            "Server-Side Request Forgery",
            SeverityLevel.MEDIUM,
        ),
    }


class AIVerificationService:
    """
    AI-powered verification service for scanner findings.

    Features:
        - Verify individual and batch findings
        - Confidence scoring (0-100)
        - False-positive detection
        - Risk analysis with CVSS estimation
        - CWE mapping
        - Thread-safe operations
        - Async support with retry logic
        - JSON export capability

    Example:
        >>> service = AIVerificationService()
        >>> result = service.verify_finding(
        ...     scanner_name="xss_scanner",
        ...     finding={"type": "xss", "payload": "<script>alert(1)</script>"},
        ...     target="https://example.com"
        ... )
        >>> print(f"Confidence: {result.confidence}%")
    """

    def __init__(
        self,
        ai_service: AIAnalysisService | None = None,
        config: VerificationConfig | None = None,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> None:
        """
        Initialize the AI verification service.

        Args:
            ai_service: AIAnalysisService instance (creates new if None)
            config: Verification configuration (uses defaults if None)
            progress_callback: Callback for progress updates
        """
        self._ai_service = ai_service
        self._config = config or VerificationConfig()
        self._progress_callback = progress_callback

        # Thread-safe state
        self._lock = threading.RLock()
        self._results: dict[UUID, VerificationResult] = {}
        self._stats = VerificationStats()
        self._running: bool = False

        # Async support
        self._async_tasks: set[asyncio.Future] = set()

        # Cache for repeated verifications
        self._cache: dict[str, VerificationResult] = {}
        self._cache_max_size: int = 1000

        # Create AI service if not provided
        if self._ai_service is None:
            self._ai_service = self._create_default_ai_service()

    def _create_default_ai_service(self):
        """
        Create a default AI analysis service.

        Returns:
            AI service instance with analyze_finding method
        """

        # Simple mock for testing/development
        class MockAIService:
            def analyze_finding(self, scanner_name, finding, target, context=None):
                return {
                    "confidence": 75.0,
                    "explanation": "Mock AI analysis - please configure real AI service",
                    "recommendations": ["Implement proper input validation"],
                    "severity": "medium",
                    "cwe_id": "CWE-79",
                    "details": {"mock": True},
                }

        # Try to create real service
        try:
            # Prefer the AIService implementation expected by AIAnalysisService
            try:
                from app.services.ai.ai_service import AIService
            except Exception:
                # Fallback for alternate module layout
                from app.services.ai_service import AIService

            # Try no-arg constructor first; if it requires positional args,
            # fall back to providing explicit None values.
            try:
                ai_service = AIService()
            except TypeError as te:
                # Some AIService implementations expect positional args
                try:
                    ai_service = AIService(
                        model_manager=None, prompt_builder=None, response_parser=None
                    )
                except TypeError:
                    # If both fail, use mock service
                    raise te
            return AIAnalysisService(ai_service=ai_service)
        except (
            ImportError,
            TypeError,
            ValueError,
            ModuleNotFoundError,
            AttributeError,
        ) as e:
            logger = logging.getLogger(__name__)
            logger.debug(f"Using mock AI service (real service not available): {e}")
            return MockAIService()

    def verify_finding(
        self,
        scanner_name: str,
        finding: dict[str, Any],
        target: str,
        context: VerificationContext | None = None,
        timeout: float | None = None,
        retry_count: int | None = None,
    ) -> VerificationResult:
        """
        Verify a single finding using AI analysis.

        Args:
            scanner_name: Name of the scanner that found the finding
            finding: Finding data dict
            target: Target being scanned
            context: Verification context (optional)
            timeout: Timeout for verification (defaults to config)
            retry_count: Retry attempts (defaults to config)

        Returns:
            VerificationResult with verification details
        """
        context = context or VerificationContext(
            target=target,
            finding_type=finding.get("type", "unknown"),
            finding_data=finding,
        )

        timeout = timeout or self._config.TIMEOUT
        retry_count = (
            retry_count if retry_count is not None else self._config.MAX_RETRIES
        )

        start_time = time.time()

        for attempt in range(retry_count + 1):
            try:
                # Check cache first
                cache_key = self._generate_cache_key(scanner_name, finding, target)
                if cache_key in self._cache:
                    return self._cache[cache_key]

                # Perform AI analysis
                analysis_result = self._ai_service.analyze_finding(
                    scanner_name=scanner_name,
                    finding=finding,
                    target=target,
                    context=context.context_data if context else {},
                )

                # Create verification result
                result = self._create_verification_result(
                    scanner_name=scanner_name,
                    finding=finding,
                    target=target,
                    analysis_result=analysis_result,
                    context=context,
                    verification_time=time.time() - start_time,
                )

                # Cache result
                self._add_to_cache(cache_key, result)

                # Update stats
                with self._lock:
                    self._update_stats(result)
                    self._results[result.verification_id] = result

                return result

            except Exception as e:  # noqa: BLE001
                if attempt >= retry_count:
                    # All retries exhausted
                    return self._create_error_result(
                        scanner_name=scanner_name,
                        finding=finding,
                        target=target,
                        error=str(e),
                        verification_time=time.time() - start_time,
                    )

                # Wait before retry
                if self._config.RETRY_DELAY > 0:
                    time.sleep(self._config.RETRY_DELAY)

        # Fallback (should never reach here)
        return self._create_error_result(
            scanner_name=scanner_name,
            finding=finding,
            target=target,
            error="Unexpected error in verification",
            verification_time=time.time() - start_time,
        )

    def verify_batch(
        self,
        findings: list[dict[str, Any]],
        scanner_name: str,
        target: str,
        context: VerificationContext | None = None,
        timeout: float | None = None,
        max_workers: int = 4,
    ) -> list[VerificationResult]:
        """
        Verify multiple findings in batch.

        Args:
            findings: List of finding dicts
            scanner_name: Name of the scanner
            target: Target being scanned
            context: Verification context (optional)
            timeout: Timeout per verification
            max_workers: Maximum parallel workers

        Returns:
            List of VerificationResult objects
        """
        if not findings:
            return []

        if len(findings) > self._config.MAX_BATCH_SIZE:
            raise ValueError(
                f"Batch size {len(findings)} exceeds maximum {self._config.MAX_BATCH_SIZE}"
            )

        results = []
        total = len(findings)

        with self._lock:
            self._running = True

        try:
            for idx, finding in enumerate(findings):
                if self._progress_callback:
                    self._progress_callback(idx + 1, total, scanner_name)

                result = self.verify_finding(
                    scanner_name=scanner_name,
                    finding=finding,
                    target=target,
                    context=context,
                    timeout=timeout,
                )
                results.append(result)
        finally:
            with self._lock:
                self._running = False

        return results

    async def verify_async(
        self,
        scanner_name: str,
        finding: dict[str, Any],
        target: str,
        context: VerificationContext | None = None,
        timeout: float | None = None,
        retry_count: int | None = None,
    ) -> VerificationResult:
        """
        Asynchronously verify a finding.

        Args:
            scanner_name: Name of the scanner
            finding: Finding data dict
            target: Target being scanned
            context: Verification context (optional)
            timeout: Timeout for verification
            retry_count: Retry attempts

        Returns:
            VerificationResult with verification details
        """
        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(
            None,
            self.verify_finding,
            scanner_name,
            finding,
            target,
            context,
            timeout,
            retry_count,
        )

        with self._lock:
            self._async_tasks.add(future)
            future.add_done_callback(lambda f: self._async_tasks.discard(f))

        return await future

    def calculate_confidence(
        self, finding: dict[str, Any], context: VerificationContext | None = None
    ) -> float:
        """
        Calculate confidence score for a finding.

        Args:
            finding: Finding data dict
            context: Verification context (optional)

        Returns:
            Confidence score (0-100)
        """
        context = context or VerificationContext(
            target="", finding_type=finding.get("type", "unknown"), finding_data=finding
        )

        # Base confidence from AI analysis
        try:
            analysis = self._ai_service.analyze_finding(
                scanner_name="unknown",
                finding=finding,
                target=context.target,
                context=context.context_data,
            )
            base_confidence = analysis.get("confidence", 50.0)
        except Exception:  # noqa: BLE001
            base_confidence = 50.0

        # Adjust based on context quality
        context_score = self._calculate_context_score(context)

        # Adjust based on finding quality
        finding_score = self._calculate_finding_score(finding)

        # Combine scores
        final_confidence = (
            (base_confidence * 0.5) + (context_score * 0.25) + (finding_score * 0.25)
        )

        # Clamp to 0-100
        return max(0.0, min(100.0, final_confidence))

    def detect_false_positive(
        self,
        finding: dict[str, Any],
        context: VerificationContext | None = None,
        analysis_result: dict[str, Any] | None = None,
    ) -> bool:
        """
        Detect if a finding is likely a false positive.

        Args:
            finding: Finding data dict
            context: Verification context (optional)
            analysis_result: Optional pre-computed analysis result

        Returns:
            True if likely false positive, False otherwise
        """
        context = context or VerificationContext(
            target="", finding_type=finding.get("type", "unknown"), finding_data=finding
        )

        # Use provided analysis result or compute confidence
        if analysis_result is not None:
            confidence = analysis_result.get("confidence", 50.0)
            is_fp_from_analysis = analysis_result.get("is_false_positive", False)
        else:
            confidence = self.calculate_confidence(finding, context)
            is_fp_from_analysis = False

        # Low confidence indicates potential false positive
        if confidence < self._config.FALSE_POSITIVE_THRESHOLD:
            return True

        # Check for common false positive patterns
        if self._has_false_positive_patterns(finding, context):
            return True

        # AI-based detection
        return bool(is_fp_from_analysis)

    def get_statistics(self) -> VerificationStats:
        """
        Get verification statistics.

        Returns:
            VerificationStats object
        """
        with self._lock:
            return self._stats

    def export_to_json(self, result: VerificationResult) -> str:
        """
        Export verification result to JSON.

        Args:
            result: VerificationResult object

        Returns:
            JSON string
        """

        def datetime_encoder(obj: Any) -> str:
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, UUID):
                return str(obj)
            if isinstance(obj, CVSSInfo):
                return {
                    "score": obj.score,
                    "vector": obj.vector,
                    "severity": obj.severity.value,
                    "metrics": obj.metrics,
                }
            if isinstance(obj, CWEInfo):
                return {
                    "id": obj.id,
                    "name": obj.name,
                    "description": obj.description,
                    "severity": obj.severity.value,
                }
            if isinstance(obj, VerificationContext):
                return {
                    "target": obj.target,
                    "finding_type": obj.finding_type,
                    "timestamp": obj.timestamp.isoformat(),
                }
            return str(obj)

        return json.dumps(result, default=datetime_encoder, indent=2, sort_keys=False)

    def clear_cache(self) -> None:
        """Clear the verification cache."""
        with self._lock:
            self._cache.clear()

    def shutdown(self) -> None:
        """
        Shutdown the verification service.

        Cancels any running verifications and cleans up resources.
        """
        with self._lock:
            self._running = False

            # Cancel async tasks
            for task in self._async_tasks:
                if not task.done():
                    task.cancel()
            self._async_tasks.clear()

            # Clear cache
            self._cache.clear()

    # Private helper methods

    def _generate_cache_key(
        self, scanner_name: str, finding: dict[str, Any], target: str
    ) -> str:
        """Generate cache key for finding."""
        key_data = f"{scanner_name}:{target}:{json.dumps(finding, sort_keys=True)}"
        return str(hash(key_data))

    def _add_to_cache(self, key: str, result: VerificationResult) -> None:
        """Add result to cache with size management."""
        with self._lock:
            if len(self._cache) >= self._cache_max_size:
                # Remove oldest entry (simple LRU)
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            self._cache[key] = result

    def _create_verification_result(
        self,
        scanner_name: str,
        finding: dict[str, Any],
        target: str,
        analysis_result: dict[str, Any],
        context: VerificationContext,
        verification_time: float,
    ) -> VerificationResult:
        """Create verification result from analysis."""
        finding_id = finding.get("id") or str(uuid4())

        # Determine verification status
        confidence = analysis_result.get("confidence", 50.0)
        false_positive_reason = analysis_result.get("false_positive_reason", "")

        # Check if confidence is below threshold (false positive)
        if confidence < self._config.FALSE_POSITIVE_THRESHOLD:
            false_positive_detected = True
            status = VerificationStatus.FALSE_POSITIVE
            verified = False
        elif confidence >= self._config.MIN_CONFIDENCE_THRESHOLD:
            false_positive_detected = False
            status = VerificationStatus.VERIFIED
            verified = True
        else:
            false_positive_detected = False
            status = VerificationStatus.INCONCLUSIVE
            verified = False

        # Also check if analysis explicitly marked as false positive
        if analysis_result.get("is_false_positive", False):
            false_positive_detected = True
            status = VerificationStatus.FALSE_POSITIVE
            verified = False

        # Determine severity
        severity = self._determine_severity(finding, analysis_result)

        # Get CWE info
        cwe = self._get_cwe_info(finding, analysis_result)

        # Calculate CVSS
        cvss = self._calculate_cvss(finding, severity, analysis_result)

        return VerificationResult(
            finding_id=finding_id,
            scanner_name=scanner_name,
            verified=verified,
            confidence=confidence,
            status=status,
            severity=severity,
            cvss=cvss,
            cwe=cwe,
            false_positive=false_positive_detected,
            false_positive_reason=false_positive_reason,
            recommendations=analysis_result.get("recommendations", []),
            explanation=analysis_result.get("explanation", ""),
            verification_time=verification_time,
            metadata={
                "target": target,
                "finding_type": finding.get("type", "unknown"),
                "analysis_details": analysis_result.get("details", {}),
            },
        )

    def _create_error_result(
        self,
        scanner_name: str,
        finding: dict[str, Any],
        target: str,
        error: str,
        verification_time: float,
    ) -> VerificationResult:
        """Create error result."""
        return VerificationResult(
            finding_id=finding.get("id") or str(uuid4()),
            scanner_name=scanner_name,
            verified=False,
            confidence=0.0,
            status=VerificationStatus.ERROR,
            severity=SeverityLevel.NONE,
            explanation=error,
            verification_time=verification_time,
            metadata={"target": target, "error": error},
        )

    def _calculate_context_score(self, context: VerificationContext) -> float:
        """Calculate score based on context quality."""
        score = 50.0

        if context.source_code:
            score += 10
        if context.request_data:
            score += 10
        if context.response_data:
            score += 10
        if context.environment:
            score += 10
        if context.context_data:
            score += 10

        return min(100.0, score)

    def _calculate_finding_score(self, finding: dict[str, Any]) -> float:
        """Calculate score based on finding quality."""
        score = 50.0

        if finding.get("type"):
            score += 10
        if finding.get("payload"):
            score += 10
        if finding.get("location"):
            score += 10
        if finding.get("evidence"):
            score += 10
        if finding.get("description"):
            score += 10

        return min(100.0, score)

    def _has_false_positive_patterns(
        self, finding: dict[str, Any], context: VerificationContext
    ) -> bool:
        """Check for common false positive patterns."""
        # Check for common false positive indicators
        finding_type = finding.get("type", "").lower()

        # XSS false positives
        if "xss" in finding_type:
            payload = str(finding.get("payload", ""))
            if "alert(" not in payload and "prompt(" not in payload:
                return True
            if "console.log" in payload:
                return True

        # SQL injection false positives
        if "sql" in finding_type:
            payload = str(finding.get("payload", ""))
            if "'" not in payload and '"' not in payload:
                return True
            if "sleep(" in payload and "benchmark(" not in payload:
                return True

        # Generic patterns
        if "test" in finding.get("description", "").lower():
            return True

        return "example" in finding.get("description", "").lower()

    def _determine_severity(
        self, finding: dict[str, Any], analysis_result: dict[str, Any]
    ) -> SeverityLevel:
        """Determine severity from finding and analysis."""
        # Try from analysis first
        severity_str = analysis_result.get("severity", "").lower()
        if severity_str:
            try:
                return SeverityLevel(severity_str)
            except ValueError:
                pass

        # Try from finding
        severity_str = finding.get("severity", "").lower()
        if severity_str:
            try:
                return SeverityLevel(severity_str)
            except ValueError:
                pass

        # Determine from type
        finding_type = finding.get("type", "").lower()
        if "critical" in finding_type:
            return SeverityLevel.CRITICAL
        if "high" in finding_type:
            return SeverityLevel.HIGH
        if "medium" in finding_type:
            return SeverityLevel.MEDIUM
        if "low" in finding_type:
            return SeverityLevel.LOW
        if "info" in finding_type:
            return SeverityLevel.INFO

        return SeverityLevel.NONE

    def _get_cwe_info(
        self, finding: dict[str, Any], analysis_result: dict[str, Any]
    ) -> CWEInfo | None:
        """Get CWE information for finding."""
        # Check analysis first
        cwe_id = analysis_result.get("cwe_id", "")
        if cwe_id and cwe_id in VerificationConfig.CWE_MAPPINGS:
            return VerificationConfig.CWE_MAPPINGS[cwe_id]

        # Check finding
        cwe_id = finding.get("cwe_id", "")
        if cwe_id and cwe_id in VerificationConfig.CWE_MAPPINGS:
            return VerificationConfig.CWE_MAPPINGS[cwe_id]

        # Map from finding type
        finding_type = finding.get("type", "").lower()
        type_to_cwe = {
            "xss": "CWE-79",
            "sqli": "CWE-89",
            "sql": "CWE-89",
            "path traversal": "CWE-22",
            "csrf": "CWE-352",
            "xxe": "CWE-611",
            "ssrf": "CWE-918",
            "auth": "CWE-287",
            "authorization": "CWE-285",
        }

        for key, cwe_id in type_to_cwe.items():
            if key in finding_type:
                return VerificationConfig.CWE_MAPPINGS.get(cwe_id)

        return None

    def _calculate_cvss(
        self,
        finding: dict[str, Any],
        severity: SeverityLevel,
        analysis_result: dict[str, Any],
    ) -> CVSSInfo:
        """Calculate CVSS score."""
        # Map severity to CVSS score
        severity_scores = {
            SeverityLevel.CRITICAL: (9.0, 10.0),
            SeverityLevel.HIGH: (7.0, 8.9),
            SeverityLevel.MEDIUM: (4.0, 6.9),
            SeverityLevel.LOW: (1.0, 3.9),
            SeverityLevel.INFO: (0.0, 0.9),
            SeverityLevel.NONE: (0.0, 0.0),
        }

        min_score, max_score = severity_scores.get(severity, (0.0, 0.0))

        # Adjust based on confidence
        confidence = analysis_result.get("confidence", 50.0)
        score_adjustment = ((confidence - 50) / 50) * 1.0  # -1.0 to +1.0

        # Calculate final score
        base_score = (min_score + max_score) / 2
        final_score = base_score + score_adjustment

        # Clamp to range
        final_score = max(min_score, min(max_score, final_score))

        # Vector string
        vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        return CVSSInfo(
            score=round(final_score, 1),
            vector=vector,
            severity=severity,
            metrics={
                "attack_vector": 1.0,
                "attack_complexity": 0.7,
                "privileges_required": 0.8,
                "user_interaction": 0.6,
                "confidentiality": 0.8,
                "integrity": 0.8,
                "availability": 0.6,
            },
        )

    def _update_stats(self, result: VerificationResult) -> None:
        """Update statistics with result."""
        if result.status == VerificationStatus.VERIFIED:
            self._stats.verified += 1
        elif result.status == VerificationStatus.FALSE_POSITIVE:
            self._stats.false_positives += 1
        elif result.status == VerificationStatus.INCONCLUSIVE:
            self._stats.inconclusive += 1
        elif result.status == VerificationStatus.ERROR:
            self._stats.errors += 1

        self._stats.total += 1
        self._stats.total_time += result.verification_time
        self._stats.avg_time = self._stats.total_time / self._stats.total

        # Update confidence
        self._stats.avg_confidence = (
            self._stats.avg_confidence * (self._stats.total - 1) + result.confidence
        ) / self._stats.total

        # Update severity counts
        severity_map = {
            SeverityLevel.CRITICAL: "critical_severity",
            SeverityLevel.HIGH: "high_severity",
            SeverityLevel.MEDIUM: "medium_severity",
            SeverityLevel.LOW: "low_severity",
        }

        if result.severity in severity_map:
            attr = severity_map[result.severity]
            setattr(self._stats, attr, getattr(self._stats, attr) + 1)
