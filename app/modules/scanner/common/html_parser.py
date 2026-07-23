# app/modules/scanner/common/html_parser.py

"""
HTML parsing utilities for SQL injection detection.
"""

import re
from typing import List, Set, Optional, Dict
from bs4 import BeautifulSoup


class HTMLParser:
    """HTML parsing utilities for SQL injection detection."""

    def __init__(self):
        """Initialize HTML parser."""
        pass

    def extract_text(self, html: str) -> str:
        """
        Extract visible text from HTML.

        Args:
            html: HTML content

        Returns:
            str: Extracted visible text
        """
        soup = BeautifulSoup(html, "html.parser")

        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()

        # Get text
        text = soup.get_text(separator=" ", strip=True)
        return text

    def extract_links(self, html: str) -> List[str]:
        """
        Extract all links from HTML.

        Args:
            html: HTML content

        Returns:
            List[str]: List of href links
        """
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for link in soup.find_all("a", href=True):
            links.append(link["href"])
        return links

    def extract_form_actions(self, html: str) -> List[str]:
        """
        Extract form actions from HTML.

        Args:
            html: HTML content

        Returns:
            List[str]: List of form actions
        """
        soup = BeautifulSoup(html, "html.parser")
        actions = []
        for form in soup.find_all("form"):
            if form.get("action"):
                actions.append(form["action"])
        return actions

    def get_elements_by_text(self, html: str, text: str) -> List[str]:
        """
        Find HTML elements containing specific text.

        Args:
            html: HTML content
            text: Text to search for

        Returns:
            List[str]: List of elements containing the text
        """
        soup = BeautifulSoup(html, "html.parser")
        elements = soup.find_all(text=re.compile(text))
        return [str(elem) for elem in elements]
