# app/modules/scanner/regex_utils.py
"""
Reusable regular expression utilities for SQL injection detection.
"""

import re
from typing import List, Optional, Pattern, Dict, Any


class RegexUtils:
    """Regex utilities for pattern matching and extraction."""

    # Oracle-specific patterns
    ORACLE_PATTERNS = {
        "oracle_error": r"ORA-\d{5}",
        "oracle_version": r"Oracle Database.*?(\d+\.\d+\.\d+\.\d+)",
        "dual": r"\bdual\b",
        "v$version": r"v\$version",
        "all_tables": r"all_tables",
        "user_tables": r"user_tables",
        "rownum": r"rownum",
        "sysdate": r"sysdate",
    }

    # Generic patterns
    GENERIC_PATTERNS = {
        "sql_keywords": r"\b(SELECT|UNION|FROM|WHERE|AND|OR|NULL|TABLE)\b",
        "database_error": r"(error|exception|warning|syntax)",
        "numbers": r"\b\d+\b",
    }

    @classmethod
    def contains_oracle_keywords(cls, text: str) -> List[str]:
        """
        Check if text contains Oracle-specific keywords.

        Args:
            text: Text to check

        Returns:
            List[str]: Found Oracle keywords
        """
        if not text:
            return []

        found_keywords = []
        text_lower = text.lower()

        oracle_keywords = [
            "oracle",
            "dual",
            "v$version",
            "all_tables",
            "user_tables",
            "rownum",
            "sysdate",
            "ora-",
        ]

        for keyword in oracle_keywords:
            if keyword in text_lower:
                found_keywords.append(keyword)

        return found_keywords

    @classmethod
    def extract_oracle_errors(cls, text: str) -> List[str]:
        """
        Extract Oracle error codes from text.

        Args:
            text: Text to extract from

        Returns:
            List[str]: Found Oracle error codes
        """
        if not text:
            return []

        pattern = cls.ORACLE_PATTERNS["oracle_error"]
        matches = re.findall(pattern, text, re.IGNORECASE)
        return matches

    @classmethod
    def extract_words(cls, text: str, min_length: int = 3) -> List[str]:
        """
        Extract all words from text with minimum length.

        Args:
            text: Text to extract from
            min_length: Minimum word length

        Returns:
            List[str]: Extracted words
        """
        if not text:
            return []

        # Split by non-alphanumeric characters
        words = re.findall(r"[a-zA-Z0-9_$]+", text)

        # Filter by minimum length
        return [w for w in words if len(w) >= min_length]

    @classmethod
    def normalize_text(cls, text: str) -> str:
        """
        Normalize text for comparison.

        Args:
            text: Text to normalize

        Returns:
            str: Normalized text
        """
        if not text:
            return ""

        # Convert to lowercase
        text = text.lower()

        # Remove extra whitespace
        text = re.sub(r"\s+", " ", text)

        # Remove punctuation
        text = re.sub(r"[^\w\s]", " ", text)

        return text.strip()

    @classmethod
    def count_pattern_occurrences(cls, text: str, pattern: str) -> int:
        """
        Count occurrences of a regex pattern in text.

        Args:
            text: Text to search
            pattern: Regex pattern

        Returns:
            int: Number of occurrences
        """
        if not text:
            return 0

        try:
            return len(re.findall(pattern, text, re.IGNORECASE))
        except re.error:
            return 0

    @classmethod
    def find_significant_changes(cls, baseline: str, response: str) -> Dict[str, Any]:
        """
        Find significant changes between baseline and response.

        Args:
            baseline: Baseline text
            response: Response text

        Returns:
            Dict: Change analysis
        """
        baseline_normalized = cls.normalize_text(baseline)
        response_normalized = cls.normalize_text(response)

        baseline_words = set(baseline_normalized.split())
        response_words = set(response_normalized.split())

        # Words that appear in response but not in baseline
        new_words = response_words - baseline_words
        removed_words = baseline_words - response_words

        # Check for Oracle-specific keywords in new words
        oracle_keywords = [
            w
            for w in new_words
            if any(
                keyword in w.lower()
                for keyword in ["oracle", "dual", "version", "banner"]
            )
        ]

        return {
            "baseline_word_count": len(baseline_words),
            "response_word_count": len(response_words),
            "new_words": list(new_words),
            "removed_words": list(removed_words),
            "oracle_keywords_found": oracle_keywords,
            "significant_change": len(new_words) > 10 or len(oracle_keywords) > 0,
        }
