"""
Centralized HTTP Client
"""

import logging
import time
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app.core.scope import ScopeManager
from app.core.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class HTTPClient:
    """Centralized HTTP client with scope enforcement and rate limiting."""

    def __init__(
        self,
        scope_manager: Optional[ScopeManager] = None,
        rate_limiter: Optional[RateLimiter] = None,
        timeout: int = 30,
        max_retries: int = 2,
        verify_ssl: bool = True,
    ):
        self.scope_manager = scope_manager
        self.rate_limiter = rate_limiter or RateLimiter()
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self._session = self._create_session()
        self._request_count = 0
        self._errors = 0

    def _create_session(self) -> requests.Session:
        """Create session with retry strategy."""
        session = requests.Session()

        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _check_scope(self, url: str) -> bool:
        """Check if URL is in scope."""
        if self.scope_manager and not self.scope_manager.is_allowed(url):
            logger.warning(f"Out of scope: {url}")
            return False
        return True

    def _wait_rate_limit(self, key: str = "default") -> None:
        """Apply rate limiting."""
        self.rate_limiter.wait(key)

    def _record_request(self, response: requests.Response, elapsed: float) -> None:
        """Record request metrics."""
        self._request_count += 1
        logger.debug(f"[HTTP] {response.status_code} {elapsed:.2f}s {response.url}")

    def _record_error(self, error: Exception) -> None:
        """Record error metrics."""
        self._errors += 1
        logger.error(f"[HTTP] Error: {error}")

    def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        timeout: Optional[int] = None,
    ) -> Optional[requests.Response]:
        """Send GET request."""
        if not self._check_scope(url):
            return None

        self._wait_rate_limit(url)

        try:
            start = time.time()
            response = self._session.get(
                url,
                params=params,
                headers=headers,
                cookies=cookies,
                timeout=timeout or self.timeout,
                verify=self.verify_ssl,
            )
            elapsed = time.time() - start
            self._record_request(response, elapsed)
            return response
        except Exception as e:
            self._record_error(e)
            return None

    def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        timeout: Optional[int] = None,
    ) -> Optional[requests.Response]:
        """Send POST request."""
        if not self._check_scope(url):
            return None

        self._wait_rate_limit(url)

        try:
            start = time.time()
            response = self._session.post(
                url,
                data=data,
                json=json,
                headers=headers,
                cookies=cookies,
                timeout=timeout or self.timeout,
                verify=self.verify_ssl,
            )
            elapsed = time.time() - start
            self._record_request(response, elapsed)
            return response
        except Exception as e:
            self._record_error(e)
            return None

    def set_headers(self, headers: Dict[str, str]) -> None:
        """Set default headers for all requests."""
        self._session.headers.update(headers)

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Set default cookies for all requests."""
        self._session.cookies.update(cookies)

    def close(self) -> None:
        """Close the session."""
        self._session.close()

    def get_metrics(self) -> Dict[str, int]:
        """Get request metrics."""
        return {
            "requests": self._request_count,
            "errors": self._errors,
        }
