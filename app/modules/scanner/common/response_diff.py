# app/modules/scanner/common/response_diff.py

"""
Response diff utilities for SQL injection detection.
"""

import difflib
from typing import List, Set, Optional, Tuple
from .html_parser import HTMLParser


class ResponseDiff:
    """Response diff utilities for SQL injection detection."""

    def __init__(self):
        """Initialize response diff utilities."""
        self.html_parser = HTMLParser()

    def diff_html(self, baseline: str, payload: str) -> str:
        """
        Perform HTML diff between baseline and payload responses.

        Args:
            baseline: Baseline HTML
            payload: Payload HTML

        Returns:
            str: Difference between the two HTMLs
        """
        # Extract visible text
        baseline_text = self.html_parser.extract_text(baseline)
        payload_text = self.html_parser.extract_text(payload)

        # Split into lines
        baseline_lines = baseline_text.splitlines()
        payload_lines = payload_text.splitlines()

        # Compute diff
        diff = difflib.unified_diff(
            baseline_lines,
            payload_lines,
            lineterm="",
            fromfile="baseline",
            tofile="payload",
        )

        # Extract only the added lines (starting with '+')
        added_lines = []
        removed_lines = []

        for line in diff:
            if (
                line.startswith("+")
                and not line.startswith("+++")
                and not line.startswith("@@")
            ):
                added_lines.append(line[1:].strip())
            elif (
                line.startswith("-")
                and not line.startswith("---")
                and not line.startswith("@@")
            ):
                removed_lines.append(line[1:].strip())

        # Return added content (what the injection inserted)
        return "\n".join(added_lines)

    def diff_content_length(self, baseline: str, payload: str) -> int:
        """
        Calculate the difference in content length.

        Args:
            baseline: Baseline HTML
            payload: Payload HTML

        Returns:
            int: Difference in content length
        """
        return abs(len(payload) - len(baseline))

    def find_new_elements(self, baseline: str, payload: str) -> List[str]:
        """
        Find new HTML elements in payload response.

        Args:
            baseline: Baseline HTML
            payload: Payload HTML

        Returns:
            List[str]: New elements found
        """
        from bs4 import BeautifulSoup

        soup_baseline = BeautifulSoup(baseline, "html.parser")
        soup_payload = BeautifulSoup(payload, "html.parser")

        # Get all text nodes from both
        baseline_texts = set(soup_baseline.get_text().split())
        payload_texts = set(soup_payload.get_text().split())

        # Find new texts
        new_texts = payload_texts - baseline_texts

        return list(new_texts)

    def get_diff_stats(self, baseline: str, payload: str) -> Dict[str, any]:
        """
        Get comprehensive diff statistics.

        Args:
            baseline: Baseline HTML
            payload: Payload HTML

        Returns:
            Dict: Diff statistics
        """
        diff_text = self.diff_html(baseline, payload)
        new_elements = self.find_new_elements(baseline, payload)

        return {
            "baseline_length": len(baseline),
            "payload_length": len(payload),
            "diff_length": len(diff_text),
            "new_elements_count": len(new_elements),
            "new_elements": new_elements[:10],  # First 10 for preview
            "diff_preview": diff_text[:500] if diff_text else "",  # First 500 chars
        }
