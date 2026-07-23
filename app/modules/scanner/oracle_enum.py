# app/modules/scanner/oracle_enum.py
"""
Oracle database detection for SentinelAI.
Phase 1: Oracle Detection Only.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
import requests

from .payloads import OracleDetectionPayloads, DetectionPayload
from .union_sqli import UnionSQLi
from .html_parser import HTMLParser
from .regex_utils import RegexUtils


@dataclass
class DetectionResult:
    """Result of Oracle detection."""

    is_oracle: bool = False  # Default value added
    score: int = 0
    threshold: int = 50
    indicators: Dict[str, int] = field(default_factory=dict)
    reason: str = ""

    def add_indicator(self, name: str, score: int):
        """Add an indicator and its score."""
        self.indicators[name] = score
        self.score += score

    def get_summary(self) -> str:
        """Get a summary of the detection result."""
        if self.is_oracle:
            return f"Oracle detected (Score: {self.score}/{self.threshold})"
        else:
            return f"Oracle not detected (Score: {self.score}/{self.threshold})"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "is_oracle": self.is_oracle,
            "score": self.score,
            "threshold": self.threshold,
            "indicators": self.indicators,
            "reason": self.reason,
        }


class OracleEnum:
    """
    Oracle database detection module.
    Phase 1: Only detects if the backend is Oracle.
    """

    # Detection thresholds and constants
    ORACLE_THRESHOLD = 50
    MIN_INDICATOR_SCORE = 5

    # Indicator weights
    INDICATOR_WEIGHTS = {
        "page_title_oracle": 10,
        "dual_success": 15,
        "v$version_success": 30,
        "oracle_error": 20,
        "oracle_keywords": 10,
        "all_tables_access": 20,
        "user_function": 15,
        "sysdate_function": 10,
        "rownum_success": 10,
        "response_significant_change": 15,
    }

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize OracleEnum module.

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
        self.payloads = OracleDetectionPayloads()

        # State
        self.baseline_response = None
        self.detection_result = None

        self.logger.info("[OracleEnum] Module initialized for Oracle detection")
        self.logger.info(f"[OracleEnum] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("OracleEnum")
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

    def _get_baseline(self, injection_point: str) -> Optional[requests.Response]:
        """
        Get baseline response for comparison.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[Response]: Baseline response
        """
        if self.baseline_response is None:
            self.logger.info("[OracleEnum] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.logger.info(
                    f"[OracleEnum] Baseline response length: {len(self.baseline_response.text)}"
                )
            else:
                self.logger.warning("[OracleEnum] Failed to get baseline response")

        return self.baseline_response

    def _check_page_title(self, response: requests.Response) -> int:
        """
        Check if page title contains Oracle indicators.

        Args:
            response: HTTP response

        Returns:
            int: Score for this indicator
        """
        title = self.html_parser.get_page_title(response.text)
        if not title:
            return 0

        title_lower = title.lower()
        score = 0

        if "oracle" in title_lower:
            score += self.INDICATOR_WEIGHTS["page_title_oracle"]
            self.logger.info(f"[OracleEnum] Page title contains 'Oracle': {title}")

        if "database" in title_lower and (
            "error" in title_lower or "exception" in title_lower
        ):
            score += 5

        return score

    def _check_indicator_in_response(
        self, response: requests.Response, indicator: str
    ) -> bool:
        """
        Check if an indicator exists in the response.

        Args:
            response: HTTP response
            indicator: String to search for

        Returns:
            bool: True if indicator found
        """
        if not response:
            return False

        return indicator.lower() in response.text.lower()

    def _extract_oracle_errors(self, response: requests.Response) -> List[str]:
        """
        Extract Oracle error codes from response.

        Args:
            response: HTTP response

        Returns:
            List[str]: Found Oracle error codes
        """
        return self.regex_utils.extract_oracle_errors(response.text)

    def _check_oracle_keywords(self, response: requests.Response) -> int:
        """
        Check for Oracle-specific keywords in response.

        Args:
            response: HTTP response

        Returns:
            int: Score for this indicator
        """
        keywords = self.regex_utils.contains_oracle_keywords(response.text)

        if keywords:
            self.logger.info(f"[OracleEnum] Found Oracle keywords: {keywords}")
            # Score based on number of keywords found
            base_score = self.INDICATOR_WEIGHTS["oracle_keywords"]
            bonus = len(keywords) * 2
            return min(base_score + bonus, 20)  # Cap at 20

        return 0

    def _analyze_response_change(
        self, response: requests.Response, baseline: requests.Response
    ) -> int:
        """
        Analyze significant changes between baseline and response.

        Args:
            response: Payload response
            baseline: Baseline response

        Returns:
            int: Score for this indicator
        """
        if not baseline or not response:
            return 0

        diff = self.html_parser.response_diff(baseline.text, response.text)

        if diff.get("significant_change", False):
            self.logger.info(f"[OracleEnum] Significant response change detected")
            self.logger.info(
                f"[OracleEnum] Response length diff: {diff.get('length_diff', 0)}"
            )
            self.logger.info(
                f"[OracleEnum] New words count: {len(diff.get('new_words', []))}"
            )

            # Additional points for Oracle keywords in new content
            new_text = " ".join(diff.get("new_words", []))
            oracle_keywords = self.regex_utils.contains_oracle_keywords(new_text)

            if oracle_keywords:
                self.logger.info(
                    f"[OracleEnum] Oracle keywords in new content: {oracle_keywords}"
                )
                return self.INDICATOR_WEIGHTS["response_significant_change"] + 5

            return self.INDICATOR_WEIGHTS["response_significant_change"]

        return 0

    def _test_payload(
        self, injection_point: str, payload: DetectionPayload
    ) -> Dict[str, Any]:
        """
        Test a single payload and evaluate response.

        Args:
            injection_point: Parameter to inject into
            payload: Detection payload to test

        Returns:
            Dict: Test results
        """
        self.logger.info(f"[OracleEnum] Testing: {payload.description}")
        self.logger.info(f"[OracleEnum] Payload: {payload.payload}")

        # Get baseline if not already available
        baseline = self._get_baseline(injection_point)

        # Send payload
        result = self.union_sqli.test_payload(
            injection_point, payload.payload, baseline
        )

        if not result["success"] or result.get("response") is None:
            self.logger.warning(
                f"[OracleEnum] Payload test failed: {payload.description}"
            )
            return {"success": False, "score": 0, "response": None}

        response = result["response"]

        # Calculate score for this payload
        score = 0
        indicators = []

        # Check for success indicators
        if payload.success_indicator:
            if self._check_indicator_in_response(response, payload.success_indicator):
                score += payload.weight
                indicators.append(f"{payload.success_indicator} found")

        # Check for Oracle errors
        errors = self._extract_oracle_errors(response)
        if errors:
            error_score = self.INDICATOR_WEIGHTS["oracle_error"]
            score += error_score
            indicators.append(f"Oracle errors: {errors}")

        # Check for Oracle keywords
        keyword_score = self._check_oracle_keywords(response)
        if keyword_score:
            score += keyword_score
            indicators.append("Oracle keywords found")

        # Check response changes
        if baseline and result["has_changed"]:
            change_score = self._analyze_response_change(response, baseline)
            if change_score:
                score += change_score
                indicators.append("Significant response change")

        # Additional checks for specific payloads
        if "dual" in payload.payload.lower():
            if self._check_indicator_in_response(response, "dual"):
                score += 5

        if "v$version" in payload.payload.lower():
            if self._check_indicator_in_response(response, "Oracle"):
                score += 10

        self.logger.info(f"[OracleEnum] Score for payload: {score}")
        self.logger.info(f"[OracleEnum] Indicators: {indicators}")

        return {
            "success": True,
            "score": score,
            "response": response,
            "indicators": indicators,
            "description": payload.description,
        }

    def detect(self, injection_point: str) -> DetectionResult:
        """
        Main detection method for Oracle.

        Args:
            injection_point: Parameter to inject into

        Returns:
            DetectionResult: Detection result with all details
        """
        self.logger.info(
            "[OracleEnum] =================================================="
        )
        self.logger.info("[OracleEnum] ORACLE DETECTION PHASE 1")
        self.logger.info(
            "[OracleEnum] =================================================="
        )

        result = DetectionResult(is_oracle=False, threshold=self.ORACLE_THRESHOLD)

        # Step 1: Check page title
        self.logger.info("[OracleEnum] Step 1: Checking page title...")
        baseline = self._get_baseline(injection_point)
        if baseline:
            title_score = self._check_page_title(baseline)
            if title_score:
                result.add_indicator("page_title_oracle", title_score)
                self.logger.info(f"[OracleEnum] Page title score: +{title_score}")

        # Step 2: Test all payloads
        self.logger.info("[OracleEnum] Step 2: Testing detection payloads...")
        payload_results = []

        for payload in self.payloads.get_all_payloads():
            test_result = self._test_payload(injection_point, payload)
            if test_result["success"] and test_result["score"] > 0:
                payload_results.append(test_result)
                result.add_indicator(
                    f"payload_{payload.description[:20]}", test_result["score"]
                )
                self.logger.info(f"[OracleEnum] Total score: +{test_result['score']}")

        # Step 3: Additional checks
        self.logger.info("[OracleEnum] Step 3: Additional checks...")

        # Check for Oracle errors in all responses
        if baseline:
            errors = self._extract_oracle_errors(baseline)
            if errors:
                result.add_indicator("oracle_errors_in_baseline", 10)
                self.logger.info(f"[OracleEnum] Oracle errors in baseline: +10")

        # Determine if Oracle is detected
        result.is_oracle = result.score >= result.threshold

        # Set reason
        if result.is_oracle:
            top_indicators = sorted(
                result.indicators.items(), key=lambda x: x[1], reverse=True
            )[:3]
            reasons = [f"{name} (+{score})" for name, score in top_indicators]
            result.reason = f"Oracle detected based on indicators: {', '.join(reasons)}"
        else:
            result.reason = f"Score {result.score} below threshold {result.threshold}"

        # Log final result
        self.logger.info(
            "[OracleEnum] =================================================="
        )
        self.logger.info("[OracleEnum] DETECTION COMPLETE")
        self.logger.info(f"[OracleEnum] Total Score: {result.score}")
        self.logger.info(f"[OracleEnum] Threshold: {result.threshold}")
        self.logger.info(f"[OracleEnum] Indicators: {result.indicators}")
        self.logger.info(f"[OracleEnum] Result: {result.get_summary()}")
        self.logger.info(
            "[OracleEnum] =================================================="
        )

        self.detection_result = result
        return result

    def is_oracle(self, injection_point: str) -> bool:
        """
        Simple boolean check if the backend is Oracle.

        Args:
            injection_point: Parameter to inject into

        Returns:
            bool: True if Oracle detected
        """
        result = self.detect(injection_point)
        return result.is_oracle

    def get_detection_score(self, injection_point: str) -> int:
        """
        Get the detection score without performing full detection.

        Args:
            injection_point: Parameter to inject into

        Returns:
            int: Detection score
        """
        if self.detection_result is None:
            self.detect(injection_point)

        return self.detection_result.score if self.detection_result else 0
