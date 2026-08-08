# app/modules/scanner/html_parser.py
"""
HTML parsing utilities for SQL injection detection.
"""

import re

from bs4 import BeautifulSoup
from typing import Any


class HTMLParser:
    """HTML parsing utilities for response analysis."""

    @staticmethod
    def extract_text(html: str) -> str:
        """
        Extract visible text from HTML, removing tags, scripts, and styles.

        Args:
            html: Raw HTML content

        Returns:
            str: Clean visible text
        """
        if not html:
            return ""

        try:
            soup = BeautifulSoup(html, "html.parser")

            # Remove script and style elements
            for element in soup(["script", "style", "noscript", "meta", "link"]):
                element.decompose()

            # Get text with proper spacing
            text = soup.get_text(separator=" ", strip=True)

            # Normalize whitespace
            text = re.sub(r"\s+", " ", text)

            return text.strip()
        except Exception:
            # Fallback to basic text extraction
            return re.sub(r"<[^>]+>", " ", html)

    @staticmethod
    def remove_html(html: str) -> str:
        """
        Remove HTML tags entirely.

        Args:
            html: Raw HTML content

        Returns:
            str: HTML-free text
        """
        return HTMLParser.extract_text(html)

    @staticmethod
    def get_page_title(html: str) -> str | None:
        """
        Extract the page title from HTML.

        Args:
            html: Raw HTML content

        Returns:
            Optional[str]: Page title or None if not found
        """
        if not html:
            return None

        try:
            soup = BeautifulSoup(html, "html.parser")
            title_tag = soup.find("title")
            if title_tag:
                return title_tag.get_text().strip()
            return None
        except Exception:
            # Fallback regex
            match = re.search(
                r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL
            )
            if match:
                return match.group(1).strip()
            return None

    @staticmethod
    def response_diff(baseline: str, response: str) -> dict[str, Any]:
        """
        Compare two HTML responses and return differences.

        Args:
            baseline: Baseline HTML
            response: Response HTML to compare

        Returns:
            Dict: Difference metrics
        """
        baseline_text = HTMLParser.extract_text(baseline)
        response_text = HTMLParser.extract_text(response)

        # Length differences
        baseline_len = len(baseline)
        response_len = len(response)

        # Text differences
        baseline_words = set(baseline_text.split())
        response_words = set(response_text.split())

        new_words = response_words - baseline_words
        removed_words = baseline_words - response_words

        # Check if response contains significant new content
        significant_change = False
        if new_words and len(new_words) > 5:
            significant_change = True

        return {
            "baseline_length": baseline_len,
            "response_length": response_len,
            "length_diff": response_len - baseline_len,
            "baseline_words": len(baseline_words),
            "response_words": len(response_words),
            "new_words": list(new_words)[:20],  # Limit to 20 for preview
            "removed_words": list(removed_words)[:20],
            "significant_change": significant_change,
        }

    @staticmethod
    def contains_text(
        html: str, text_patterns: list[str], case_sensitive: bool = False
    ) -> bool:
        """
        Check if HTML contains any of the given text patterns.

        Args:
            html: HTML content
            text_patterns: List of patterns to search for
            case_sensitive: Whether search should be case-sensitive

        Returns:
            bool: True if any pattern is found
        """
        if not html or not text_patterns:
            return False

        content = html if case_sensitive else html.lower()

        for pattern in text_patterns:
            search_pattern = pattern if case_sensitive else pattern.lower()
            if search_pattern in content:
                return True

        return False

    @staticmethod
    def extract_patterns(html: str, patterns: list[str]) -> list[str]:
        """
        Extract specific patterns from HTML.

        Args:
            html: HTML content
            patterns: List of regex patterns

        Returns:
            List[str]: All matches found
        """
        if not html or not patterns:
            return []

        matches = []
        for pattern in patterns:
            found = re.findall(pattern, html, re.IGNORECASE | re.MULTILINE)
            matches.extend(found)

        return list(set(matches))  # Remove duplicates
