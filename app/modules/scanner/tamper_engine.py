# app/modules/scanner/tamper_engine.py
"""
Payload Tamper Engine for SentinelAI.
Phase 15: Payload Tampering and Evasion
"""

import logging
import random
import re
import string
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# ============================================================
# Data Classes
# ============================================================


@dataclass
class TamperResult:
    """
    Tamper engine result.
    Contains tampered payload and metadata.
    """

    original_payload: str = ""
    tampered_payload: str = ""
    tamper_chain: list[str] = field(default_factory=list)
    confidence: int = 0
    success: bool = False
    errors: list[str] = field(default_factory=list)
    execution_time: float = 0.0
    tamper_count: int = 0

    def add_error(self, error: str):
        """Add an error to the result."""
        if error and error not in self.errors:
            self.errors.append(error)

    def get_summary(self) -> str:
        """Get a summary of the tamper result."""
        if not self.success:
            return f"Tampering failed: {', '.join(self.errors[:2]) if self.errors else 'Unknown error'}"

        parts = []
        if self.tamper_chain:
            parts.append(f"Chain: {', '.join(self.tamper_chain)}")
        if self.tamper_count > 0:
            parts.append(f"Tampers: {self.tamper_count}")
        if self.confidence > 0:
            parts.append(f"Confidence: {self.confidence}%")

        return f"Tamper: {', '.join(parts)}" if parts else "Tamper: No changes applied"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "original_payload": self.original_payload,
            "tampered_payload": self.tampered_payload,
            "tamper_chain": self.tamper_chain,
            "confidence": self.confidence,
            "success": self.success,
            "errors": self.errors,
            "execution_time": self.execution_time,
            "tamper_count": self.tamper_count,
            "summary": self.get_summary(),
        }


# ============================================================
# Tamper Engine Class
# ============================================================


class TamperEngine:
    """
    Payload Tamper Engine for SQL injection evasion.
    Phase 15: Applies various tampering techniques to evade WAFs.
    """

    # ============================================================
    # Constants
    # ============================================================

    # WAF-specific recommendations
    WAF_RECOMMENDATIONS = {
        "Cloudflare": [
            "random_case",
            "url_encode",
            "inline_comment",
            "space_to_comment",
            "mixed_encoding",
        ],
        "ModSecurity": [
            "space_to_comment",
            "inline_comment",
            "keyword_split",
            "version_comment",
            "char_encode",
        ],
        "AWS WAF": [
            "url_encode",
            "double_url_encode",
            "unicode_encode",
            "random_case",
            "space_to_plus",
        ],
        "Imperva SecureSphere": [
            "space_to_newline",
            "append_comment",
            "random_case",
            "inline_comment",
            "keyword_split",
        ],
        "Sucuri": [
            "space_to_tab",
            "url_encode",
            "random_case",
            "percentage_encode",
            "mixed_encoding",
        ],
        "Barracuda": [
            "inline_comment",
            "space_to_comment",
            "random_case",
            "double_url_encode",
            "keyword_split",
        ],
        "F5 BIG-IP ASM": [
            "space_to_newline",
            "append_comment",
            "url_encode",
            "case_randomizer",
            "inline_comment",
        ],
        "FortiWeb": [
            "space_to_tab",
            "char_encode",
            "random_case",
            "percentage_encode",
            "mixed_encoding",
        ],
        "Akamai": [
            "url_encode",
            "double_url_encode",
            "unicode_encode",
            "random_case",
            "space_to_comment",
        ],
        "General": [
            "random_case",
            "url_encode",
            "inline_comment",
            "space_to_comment",
            "mixed_encoding",
        ],
    }

    # Confidence scores for each tamper
    TAMPER_CONFIDENCE = {
        "random_case": 60,
        "space_to_comment": 75,
        "space_to_plus": 40,
        "space_to_tab": 45,
        "space_to_newline": 50,
        "url_encode": 70,
        "double_url_encode": 80,
        "unicode_encode": 75,
        "char_encode": 65,
        "percentage_encode": 70,
        "append_comment": 55,
        "inline_comment": 80,
        "keyword_split": 75,
        "version_comment": 65,
        "mixed_encoding": 85,
        "case_randomizer": 50,
    }

    # ============================================================
    # Initialization
    # ============================================================

    def __init__(self, logger: logging.Logger | None = None):
        """
        Initialize Tamper Engine.

        Args:
            logger: Optional logger instance
        """
        self.logger = logger or self._setup_logger()
        self._tamper_registry = self._register_tampers()

        self.logger.info(
            "[TamperEngine] Module initialized with %d tampers",
            len(self._tamper_registry),
        )

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("TamperEngine")
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
    # Core Tamper Methods
    # ============================================================

    def _register_tampers(self) -> dict[str, Callable]:
        """Register all tamper methods."""
        return {
            "random_case": self._tamper_random_case,
            "space_to_comment": self._tamper_space_to_comment,
            "space_to_plus": self._tamper_space_to_plus,
            "space_to_tab": self._tamper_space_to_tab,
            "space_to_newline": self._tamper_space_to_newline,
            "url_encode": self._tamper_url_encode,
            "double_url_encode": self._tamper_double_url_encode,
            "unicode_encode": self._tamper_unicode_encode,
            "char_encode": self._tamper_char_encode,
            "percentage_encode": self._tamper_percentage_encode,
            "append_comment": self._tamper_append_comment,
            "inline_comment": self._tamper_inline_comment,
            "keyword_split": self._tamper_keyword_split,
            "version_comment": self._tamper_version_comment,
            "mixed_encoding": self._tamper_mixed_encoding,
            "case_randomizer": self._tamper_case_randomizer,
        }

    # ============================================================
    # Individual Tamper Methods
    # ============================================================

    def _tamper_random_case(self, payload: str) -> str:
        """
        Randomize case of alphabetic characters.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        result = []
        for char in payload:
            if char.isalpha():
                result.append(
                    char.upper() if random.choice([True, False]) else char.lower()
                )
            else:
                result.append(char)
        return "".join(result)

    def _tamper_space_to_comment(self, payload: str) -> str:
        """
        Replace spaces with inline comments /**/.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        return payload.replace(" ", "/**/")

    def _tamper_space_to_plus(self, payload: str) -> str:
        """
        Replace spaces with plus signs.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        return payload.replace(" ", "+")

    def _tamper_space_to_tab(self, payload: str) -> str:
        """
        Replace spaces with tabs.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        return payload.replace(" ", "\t")

    def _tamper_space_to_newline(self, payload: str) -> str:
        """
        Replace spaces with newlines.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        return payload.replace(" ", "\n")

    def _tamper_url_encode(self, payload: str) -> str:
        """
        URL encode special characters.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        return urllib.parse.quote(payload, safe="")

    def _tamper_double_url_encode(self, payload: str) -> str:
        """
        Double URL encode special characters.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        encoded = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(encoded, safe="")

    def _tamper_unicode_encode(self, payload: str) -> str:
        """
        Encode characters as Unicode (%uXXXX).

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        result = []
        for char in payload:
            if char.isalnum() or char in " _-.":
                result.append(char)
            else:
                result.append(f"%u{ord(char):04x}")
        return "".join(result)

    def _tamper_char_encode(self, payload: str) -> str:
        """
        Encode characters using CHAR() function.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        result = []
        for char in payload:
            if char.isalnum() or char in " _-.!?":
                result.append(char)
            else:
                result.append(f"CHAR({ord(char)})")
        return "".join(result)

    def _tamper_percentage_encode(self, payload: str) -> str:
        """
        Percentage encode using %NN format.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        result = []
        for char in payload:
            if char.isalnum() or char in " _-.":
                result.append(char)
            else:
                result.append(f"%{ord(char):02x}")
        return "".join(result)

    def _tamper_append_comment(self, payload: str) -> str:
        """
        Append a random comment at the end.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        comment = f"/*{''.join(random.choices(string.ascii_lowercase, k=5))}*/"
        return payload + comment

    def _tamper_inline_comment(self, payload: str) -> str:
        """
        Insert inline comments between keywords.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        # Split by spaces and insert comments
        words = payload.split()
        if len(words) <= 1:
            return payload

        result = []
        for i, word in enumerate(words):
            if i > 0:
                comment = f"/*{''.join(random.choices(string.ascii_lowercase, k=3))}*/"
                result.append(comment)
            result.append(word)

        return " ".join(result)

    def _tamper_keyword_split(self, payload: str) -> str:
        """
        Split keywords with inline comments.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "ORDER", "BY"]

        result = payload
        for keyword in keywords:
            if keyword in result.upper():
                pattern = keyword
                replacement = f"{keyword[0]}/**/{keyword[1:]}"
                result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

        return result

    def _tamper_version_comment(self, payload: str) -> str:
        """
        Add Oracle version comment.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        version_comments = [
            "/*!40101*/",
            "/*!40100*/",
            "/*!40000*/",
        ]
        comment = random.choice(version_comments)
        return f"{comment} {payload}"

    def _tamper_mixed_encoding(self, payload: str) -> str:
        """
        Apply mixed encoding techniques.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        result = []
        for char in payload:
            if char.isalpha():
                # Randomly encode with different methods
                choice = random.choice(["upper", "lower", "hex", "char"])
                if choice == "upper":
                    result.append(char.upper())
                elif choice == "lower":
                    result.append(char.lower())
                elif choice == "hex":
                    result.append(f"%{ord(char):02x}")
                elif choice == "char":
                    result.append(f"CHAR({ord(char)})")
            else:
                result.append(char)
        return "".join(result)

    def _tamper_case_randomizer(self, payload: str) -> str:
        """
        Completely randomize case of all letters.

        Args:
            payload: Original payload

        Returns:
            str: Tampered payload
        """
        return "".join(
            char.upper() if random.choice([True, False]) else char.lower()
            for char in payload
        )

    # ============================================================
    # Public Methods
    # ============================================================

    def apply(self, payload: str, tamper_name: str) -> TamperResult:
        """
        Apply a single tamper to a payload.

        Args:
            payload: Original payload
            tamper_name: Name of tamper to apply

        Returns:
            TamperResult: Tamper result
        """
        import time

        start_time = time.time()

        result = TamperResult(original_payload=payload, tamper_chain=[tamper_name])

        try:
            if tamper_name not in self._tamper_registry:
                result.add_error(f"Unknown tamper: {tamper_name}")
                result.success = False
                return result

            tamper_func = self._tamper_registry[tamper_name]
            tampered = tamper_func(payload)

            result.tampered_payload = tampered
            result.success = True
            result.tamper_count = 1
            result.confidence = self.TAMPER_CONFIDENCE.get(tamper_name, 50)

            self.logger.info(
                f"[TamperEngine] Applied {tamper_name}: {payload[:30]}... -> {tampered[:30]}..."
            )

        except Exception as e:
            result.add_error(f"Tamper failed: {e!s}")
            result.success = False
            self.logger.error(f"[TamperEngine] Failed to apply {tamper_name}: {e!s}")

        result.execution_time = time.time() - start_time
        return result

    def apply_chain(self, payload: str, tamper_chain: list[str]) -> TamperResult:
        """
        Apply multiple tampers in sequence.

        Args:
            payload: Original payload
            tamper_chain: List of tamper names

        Returns:
            TamperResult: Tamper result
        """
        import time

        start_time = time.time()

        result = TamperResult(original_payload=payload, tamper_chain=tamper_chain)

        # If chain is empty, return empty payload with success=False
        if not tamper_chain:
            result.tampered_payload = ""
            result.success = False
            result.tamper_count = 0
            result.confidence = 0
            result.add_error("Empty tamper chain provided")
            result.execution_time = time.time() - start_time
            self.logger.warning(
                "[TamperEngine] Empty chain provided, no tampers applied"
            )
            return result

        current_payload = payload
        applied = []
        total_confidence = 0

        for tamper_name in tamper_chain:
            try:
                if tamper_name not in self._tamper_registry:
                    result.add_error(f"Unknown tamper: {tamper_name}")
                    continue

                tamper_func = self._tamper_registry[tamper_name]
                current_payload = tamper_func(current_payload)
                applied.append(tamper_name)
                total_confidence += self.TAMPER_CONFIDENCE.get(tamper_name, 50)

                self.logger.debug(f"[TamperEngine] Applied {tamper_name} in chain")

            except Exception as e:
                result.add_error(f"Tamper {tamper_name} failed: {e!s}")
                self.logger.error(
                    f"[TamperEngine] Chain tamper {tamper_name} failed: {e!s}"
                )

        result.tampered_payload = current_payload
        result.success = len(applied) > 0
        result.tamper_count = len(applied)
        result.confidence = (
            min(total_confidence // max(len(applied), 1), 100) if applied else 0
        )

        result.execution_time = time.time() - start_time

        if result.success:
            self.logger.info(f"[TamperEngine] Applied chain of {len(applied)} tampers")
        else:
            self.logger.warning("[TamperEngine] Chain tampering failed")

        return result

    def list_tampers(self) -> list[str]:
        """
        List all available tamper methods.

        Returns:
            List[str]: List of tamper names
        """
        return list(self._tamper_registry.keys())

    def recommend_tampers(self, waf_name: str) -> list[str]:
        """
        Recommend tampers for a specific WAF.

        Args:
            waf_name: Name of the WAF

        Returns:
            List[str]: Recommended tamper names
        """
        # Case-insensitive matching
        for key in self.WAF_RECOMMENDATIONS:
            if key.lower() in waf_name.lower() or waf_name.lower() in key.lower():
                self.logger.info(
                    f"[TamperEngine] Found recommendations for {waf_name} (matched {key})"
                )
                return self.WAF_RECOMMENDATIONS[key]

        # Try partial match
        for key in self.WAF_RECOMMENDATIONS:
            for word in key.split():
                if word.lower() in waf_name.lower():
                    self.logger.info(
                        f"[TamperEngine] Partial match for {waf_name} (matched {key})"
                    )
                    return self.WAF_RECOMMENDATIONS[key]

        # Default recommendations
        self.logger.info(f"[TamperEngine] Using general recommendations for {waf_name}")
        return self.WAF_RECOMMENDATIONS["General"]

    def get_tamper_confidence(self, tamper_name: str) -> int:
        """
        Get confidence score for a tamper.

        Args:
            tamper_name: Name of tamper

        Returns:
            int: Confidence score (0-100)
        """
        return self.TAMPER_CONFIDENCE.get(tamper_name, 50)

    def test_tamper(self, payload: str, tamper_name: str) -> bool:
        """
        Test if a tamper modifies the payload.

        Args:
            payload: Original payload
            tamper_name: Name of tamper

        Returns:
            bool: True if tamper modifies payload
        """
        result = self.apply(payload, tamper_name)
        return result.success and result.tampered_payload != payload
