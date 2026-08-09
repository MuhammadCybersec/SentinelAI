"""
Scope-Aware Web Crawler
"""

import logging
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from app.core.http_client import HTTPClient
from app.core.scope import ScopeManager
from app.modules.recon.url_normalizer import normalize_url

logger = logging.getLogger(__name__)


class ScopedCrawler:
    """
    Scope-aware crawler that respects target scope.
    """

    def __init__(
        self,
        http_client: HTTPClient,
        scope_manager: ScopeManager,
        max_depth: int = 3,
        max_urls: int = 500,
    ):
        self.http_client = http_client
        self.scope_manager = scope_manager
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited: Set[str] = set()
        self.discovered: Set[str] = set()
        self.forms: List[Dict] = []
        self.endpoints: List[Dict] = []

    def crawl(self, start_url: str, depth: int = 0) -> List[str]:
        """
        Crawl starting from URL up to max_depth.

        Returns:
            List of discovered URLs in scope.
        """
        if depth > self.max_depth:
            return []

        if len(self.discovered) >= self.max_urls:
            return []

        # Normalize and check scope
        url = normalize_url(start_url)
        if not self.scope_manager.is_allowed(url):
            logger.debug(f"Out of scope: {url}")
            return []

        if url in self.visited:
            return []

        self.visited.add(url)
        self.discovered.add(url)

        # Fetch the page
        response = self.http_client.get(url)
        if not response or response.status_code != 200:
            return []

        # Extract links
        links = self._extract_links(response.text, url)
        self.discovered.update(links)

        # Extract forms
        forms = self._extract_forms(response.text, url)
        self.forms.extend(forms)

        # Extract endpoints
        endpoints = self._extract_endpoints(response.text, url)
        self.endpoints.extend(endpoints)

        # Recursively crawl links
        for link in links:
            if len(self.discovered) >= self.max_urls:
                break
            self.crawl(link, depth + 1)

        return list(self.discovered)

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract internal links from HTML."""
        links = []
        soup = BeautifulSoup(html, "html.parser")

        for tag in soup.find_all("a", href=True):
            href = tag.get("href", "").strip()
            if not href or href.startswith("#") or href.startswith("javascript:"):
                continue

            absolute = urljoin(base_url, href)
            absolute = normalize_url(absolute)

            if self.scope_manager.is_allowed(absolute):
                links.append(absolute)

        return links

    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract forms from HTML."""
        forms = []
        soup = BeautifulSoup(html, "html.parser")

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            action_url = urljoin(base_url, action)
            action_url = normalize_url(action_url)

            if not self.scope_manager.is_allowed(action_url):
                continue

            inputs = []
            for input_tag in form.find_all("input"):
                name = input_tag.get("name")
                if name:
                    inputs.append(
                        {
                            "name": name,
                            "type": input_tag.get("type", "text"),
                            "value": input_tag.get("value", ""),
                        }
                    )

            forms.append(
                {
                    "url": action_url,
                    "method": method,
                    "inputs": inputs,
                }
            )

        return forms

    def _extract_endpoints(self, html: str, base_url: str) -> List[Dict]:
        """Extract API endpoints from HTML."""
        endpoints = []
        # This is a basic implementation - can be enhanced
        return endpoints

    def get_results(self) -> Dict:
        """Get crawler results."""
        return {
            "urls": list(self.discovered),
            "forms": self.forms,
            "endpoints": self.endpoints,
            "total_visited": len(self.visited),
            "total_discovered": len(self.discovered),
        }
