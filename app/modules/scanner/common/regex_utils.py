# app/modules/scanner/common/regex_utils.py

"""
Regular expression utilities for data extraction.
"""

import re
from typing import List, Set, Optional, Dict, Pattern


class RegexUtils:
    """Regular expression utilities for data extraction."""

    def __init__(self):
        """Initialize regex utilities."""
        self.patterns = {
            "table_name": r"[A-Z][A-Z0-9_$]{2,}",
            "column_name": r"[A-Z][A-Z0-9_$]{2,}",
            "oracle_error": r"(ORA-\d{5})",
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "username_like": r"^(USERNAME|USER|LOGIN|EMAIL|ACCOUNT)$",
            "password_like": r"^(PASSWORD|PASS|PWD|HASH|SECRET)$",
            "admin_like": r"^(ADMINISTRATOR|ADMIN|ROOT)$",
            "hash": r"[a-fA-F0-9]{32,}",
            "numeric": r"\b\d+\b",
        }

    def extract_pattern(self, text: str, pattern: str) -> List[str]:
        """
        Extract all matches for a pattern.

        Args:
            text: Text to extract from
            pattern: Regex pattern

        Returns:
            List[str]: All matches
        """
        matches = re.findall(pattern, text, re.IGNORECASE)
        return matches

    def extract_table_names(self, text: str) -> List[str]:
        """
        Extract potential table names from text.

        Args:
            text: Text to extract from

        Returns:
            List[str]: Extracted table names
        """
        return self.extract_pattern(text, self.patterns["table_name"])

    def extract_column_names(self, text: str) -> List[str]:
        """
        Extract potential column names from text.

        Args:
            text: Text to extract from

        Returns:
            List[str]: Extracted column names
        """
        return self.extract_pattern(text, self.patterns["column_name"])

    def extract_oracle_errors(self, text: str) -> List[str]:
        """
        Extract Oracle error codes from text.

        Args:
            text: Text to extract from

        Returns:
            List[str]: Oracle error codes
        """
        return self.extract_pattern(text, self.patterns["oracle_error"])

    def extract_emails(self, text: str) -> List[str]:
        """
        Extract email addresses from text.

        Args:
            text: Text to extract from

        Returns:
            List[str]: Email addresses
        """
        return self.extract_pattern(text, self.patterns["email"])

    def extract_hashes(self, text: str) -> List[str]:
        """
        Extract hash strings from text.

        Args:
            text: Text to extract from

        Returns:
            List[str]: Hash strings
        """
        return self.extract_pattern(text, self.patterns["hash"])

    def extract_numbers(self, text: str) -> List[str]:
        """
        Extract numeric values from text.

        Args:
            text: Text to extract from

        Returns:
            List[str]: Numeric values
        """
        return self.extract_pattern(text, self.patterns["numeric"])

    def is_username_like(self, text: str) -> bool:
        """
        Check if text looks like a username column.

        Args:
            text: Text to check

        Returns:
            bool: True if username-like
        """
        return bool(re.match(self.patterns["username_like"], text.upper()))

    def is_password_like(self, text: str) -> bool:
        """
        Check if text looks like a password column.

        Args:
            text: Text to check

        Returns:
            bool: True if password-like
        """
        return bool(re.match(self.patterns["password_like"], text.upper()))

    def is_admin_like(self, text: str) -> bool:
        """
        Check if text looks like an administrator.

        Args:
            text: Text to check

        Returns:
            bool: True if admin-like
        """
        return bool(re.match(self.patterns["admin_like"], text.upper()))
