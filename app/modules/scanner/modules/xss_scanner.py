"""
===========================================================
Project : Sentinel AI
Module  : XSS Scanner
File ID : SCANNER-MODULES-XSS-001
Version : 2.0.0
===========================================================

Description:

XSS (Cross-Site Scripting) vulnerability scanner.

Detects:
- Reflected XSS
- Stored XSS
- DOM-based XSS

===========================================================
"""

from __future__ import annotations

import re
import time
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from app.modules.recon.scope_manager import ScopeManager
from app.modules.scanner.core.base_scanner import (
    BaseScanner,
    ScannerConfig,
    ScanResult,
)


class XSSScanner(BaseScanner):
    """
    XSS (Cross-Site Scripting) vulnerability scanner.

    Detects Reflected, Stored, and DOM-based XSS vulnerabilities.
    """

    # XSS payloads for testing (ClassVar for immutable class attributes)
    DEFAULT_PAYLOADS: ClassVar[list[str]] = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "'\"><script>alert('XSS')</script>",
        "<svg/onload=alert('XSS')>",
        "<body/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<img/src=x/onerror=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<details open ontoggle=alert('XSS')>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
    ]

    # DOM XSS indicators (ClassVar for immutable class attributes)
    DOM_INDICATORS: ClassVar[list[str]] = [
        "document.write",
        "document.writeln",
        "innerHTML",
        "outerHTML",
        "eval",
        "setTimeout",
        "setInterval",
        "Function",
        "location",
        "document.URL",
        "document.documentURI",
        "document.baseURI",
        "document.cookie",
        "document.referrer",
        "window.name",
        "window.location",
        "window.postMessage",
    ]

    def __init__(
        self,
        target: str,
        scope: ScopeManager | None = None,
        config: ScannerConfig | None = None,
        payloads: list[str] | None = None,
        timeout: float = 30.0,
        max_params: int = 50,
    ) -> None:
        """
        Initialize the XSS Scanner.

        Args:
            target: Target URL
            scope: Scope manager for URL filtering
            config: Scanner configuration
            payloads: Custom payloads (overrides defaults)
            timeout: Request timeout in seconds
            max_params: Maximum parameters to test
        """
        super().__init__(target, scope, config)

        self.payloads = payloads or list(self.DEFAULT_PAYLOADS)
        self.timeout = timeout
        self.max_params = max_params
        self.version = "2.0.0"

        # Track tested parameters to avoid duplicates
        self._tested_params: set[str] = set()
        self._tested_endpoints: set[str] = set()

        self.logger.info(f"XSSScanner initialized with {len(self.payloads)} payloads")

    # ===========================================================
    # Main Scan Method
    # ===========================================================

    def run(self) -> list[ScanResult]:
        """
        Execute XSS scan on the target.

        Returns:
            list[ScanResult]: List of scan results
        """
        self.start_scan()
        self.logger.info(f"Starting XSS scan on: {self.target}")

        try:
            # Discover endpoints
            endpoints = self._discover_endpoints()

            for endpoint in endpoints:
                if not self.in_scope(endpoint):
                    continue

                self.logger.debug(f"Testing endpoint: {endpoint}")
                self._test_endpoint(endpoint)

            # Test parameters on target URL
            self._test_parameters(self.target)

        except (requests.RequestException, ValueError, TypeError) as e:
            self.logger.error(f"XSS scan failed: {e!s}")
            self.record_error()
        except Exception as e:  # noqa: BLE001
            self.logger.error(f"XSS scan failed with unexpected error: {e!s}")
            self.record_error()

        self.finish_scan()
        self.logger.info(
            f"XSS scan complete. Found {len(self.findings)} vulnerabilities."
        )

        return self.findings

    # ===========================================================
    # Endpoint Discovery
    # ===========================================================

    def _discover_endpoints(self) -> list[str]:
        """
        Discover endpoints from the target.

        Returns:
            list[str]: List of endpoints
        """
        endpoints = [self.target]

        try:
            # Send initial request to discover links
            response = self.safe_get(self.target)
            if response:
                # Extract links from response body
                links = self._extract_links(response.body)
                endpoints.extend(links[:20])  # Limit to 20 links

            # Add common endpoints
            common_endpoints = [
                "/search",
                "/q",
                "/s",
                "/query",
                "/find",
                "/lookup",
                "/filter",
                "/category",
                "/product",
                "/view",
                "/detail",
                "/profile",
                "/user",
                "/account",
                "/settings",
                "/admin",
                "/login",
                "/register",
                "/contact",
                "/feedback",
            ]

            parsed_url = urlparse(self.target)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

            for ep in common_endpoints:
                endpoints.append(f"{base_url}{ep}")

        except (requests.RequestException, ValueError, TypeError) as e:
            self.logger.debug(f"Endpoint discovery error: {e!s}")
        except Exception as e:  # noqa: BLE001
            self.logger.debug(f"Endpoint discovery unexpected error: {e!s}")

        return list(set(endpoints))[:50]  # Remove duplicates, limit to 50

    def _extract_links(self, html: str) -> list[str]:
        """
        Extract links from HTML.

        Args:
            html: HTML content

        Returns:
            list[str]: List of links
        """
        links = []

        # Extract href attributes
        href_pattern = re.compile(r'href=[\'"]?([^\'" >]+)')
        for match in href_pattern.finditer(html):
            link = match.group(1)
            if link and not link.startswith(("#", "mailto:", "tel:", "javascript:")):
                # Resolve relative URLs
                if link.startswith("/"):
                    parsed_url = urlparse(self.target)
                    link = f"{parsed_url.scheme}://{parsed_url.netloc}{link}"
                elif link.startswith("http"):
                    # Absolute URL
                    pass
                else:
                    # Relative URL
                    parsed_url = urlparse(self.target)
                    base = parsed_url.path.rstrip("/") if parsed_url.path else ""
                    if not link.startswith("/") and base:
                        link = f"{parsed_url.scheme}://{parsed_url.netloc}{base}/{link}"
                    elif not link.startswith("/"):
                        link = f"{parsed_url.scheme}://{parsed_url.netloc}/{link}"

                if link and self.in_scope(link):
                    links.append(link)

        return list(set(links))[:10]  # Limit to 10 links

    # ===========================================================
    # Parameter Testing
    # ===========================================================

    def _test_parameters(self, url: str) -> None:
        """
        Test parameters on a URL for XSS.

        Args:
            url: URL to test
        """
        if url in self._tested_endpoints:
            return
        self._tested_endpoints.add(url)

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            # Try common parameters
            common_params = [
                "q",
                "s",
                "search",
                "query",
                "id",
                "page",
                "filter",
                "category",
            ]
            params = {p: ["test"] for p in common_params}

        # Limit number of parameters
        param_keys = list(params.keys())[: self.max_params]

        for param in param_keys:
            if param in self._tested_params:
                continue
            self._tested_params.add(param)

            original_values = params.get(param, [""])

            for payload in self.payloads[:10]:  # Limit payloads per parameter
                self._test_payload(url, param, payload, original_values)

    def _test_endpoint(self, url: str) -> None:
        """
        Test an endpoint for XSS.

        Args:
            url: Endpoint URL
        """
        if url in self._tested_endpoints:
            return
        self._tested_endpoints.add(url)

        # Test parameters
        self._test_parameters(url)

        # Test path injection
        for payload in self.payloads[:5]:
            test_url = url.rstrip("/") + "/" + payload.replace("/", "%2F")
            self._test_payload(test_url, "path", payload, [])

    # ===========================================================
    # Payload Testing
    # ===========================================================

    def _test_payload(
        self,
        url: str,
        parameter: str,
        payload: str,
        original_values: list[str],
    ) -> None:
        """
        Test a single payload on a parameter.

        Args:
            url: Target URL
            parameter: Parameter name
            payload: Payload to test
            original_values: Original parameter values
        """
        start_time = time.perf_counter()

        try:
            # Build test URL
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if parameter == "path":
                test_url = url
            else:
                # Inject payload into parameter
                params[parameter] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment,
                    )
                )

            # Send request
            response = self.safe_get(test_url)
            response_time = time.perf_counter() - start_time

            if not response:
                return

            status_code = response.status_code
            response_body = response.body

            # Check for reflection
            reflected = self._check_reflection(payload, response_body)

            # Check for script execution
            executed = self._check_execution(payload, response_body)

            # Check for DOM XSS
            dom_vulnerable = self._check_dom_vulnerability(response_body)

            # Determine vulnerability type and severity
            if executed:
                self._create_xss_finding(
                    url=test_url,
                    parameter=parameter,
                    payload=payload,
                    evidence=response_body[:500],
                    vulnerability_type=(
                        "stored_xss"
                        if self._is_stored(response_body, payload)
                        else "reflected_xss"
                    ),
                    severity=(
                        "critical"
                        if self._is_stored(response_body, payload)
                        else "high"
                    ),
                    confidence=0.95,
                    status_code=status_code,
                    response_time=response_time,
                    description="XSS payload executed successfully",
                    remediation=self._get_remediation(parameter),
                )
            elif reflected:
                self._create_xss_finding(
                    url=test_url,
                    parameter=parameter,
                    payload=payload,
                    evidence=response_body[:500],
                    vulnerability_type="reflected_xss",
                    severity="high",
                    confidence=0.80,
                    status_code=status_code,
                    response_time=response_time,
                    description="XSS payload reflected in response",
                    remediation=self._get_remediation(parameter),
                )
            elif dom_vulnerable:
                self._create_xss_finding(
                    url=test_url,
                    parameter=parameter,
                    payload=payload,
                    evidence=response_body[:500],
                    vulnerability_type="dom_xss",
                    severity="medium",
                    confidence=0.60,
                    status_code=status_code,
                    response_time=response_time,
                    description="DOM-based XSS detected",
                    remediation=self._get_dom_remediation(),
                )
            else:
                # Check if payload appears in response (pattern match)
                pattern_match = self._check_pattern_match(payload, response_body)
                if pattern_match:
                    self._create_xss_finding(
                        url=test_url,
                        parameter=parameter,
                        payload=payload,
                        evidence=response_body[:500],
                        vulnerability_type="xss_pattern",
                        severity="medium",
                        confidence=0.50,
                        status_code=status_code,
                        response_time=response_time,
                        description="XSS pattern detected in response",
                        remediation=self._get_remediation(parameter),
                    )

        except (requests.RequestException, ValueError, TypeError) as e:
            self.logger.debug(f"Payload test failed for {parameter}: {e!s}")
        except Exception as e:  # noqa: BLE001
            self.logger.debug(f"Payload test unexpected error for {parameter}: {e!s}")

    # ===========================================================
    # Detection Methods
    # ===========================================================

    def _check_reflection(self, payload: str, response: str) -> bool:
        """
        Check if payload is reflected in the response.

        Args:
            payload: XSS payload
            response: Response text

        Returns:
            bool: True if reflected
        """
        # Check for exact match (case sensitive)
        if payload in response:
            return True

        # Check for URL-encoded version
        import urllib.parse

        encoded = urllib.parse.quote(payload)
        if encoded in response:
            return True

        # Check for HTML-encoded version
        html_encoded = (
            payload.replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
        if html_encoded in response:
            return True

        # Check for partial matches
        payload_parts = re.findall(r"[a-zA-Z]+", payload)
        for part in payload_parts:
            if len(part) > 3 and part in response:
                return True

        return False

    def _check_execution(self, payload: str, response: str) -> bool:
        """
        Check if script execution is indicated in the response.

        Args:
            payload: XSS payload
            response: Response text

        Returns:
            bool: True if execution indicated
        """
        # Check for alert pattern
        if re.search(r"alert\s*\(", response, re.IGNORECASE):
            return True

        # Check for script execution indicators
        execution_indicators = [
            "onerror=",
            "onload=",
            "onfocus=",
            "onclick=",
            "onmouseover=",
            "javascript:",
            "eval(",
            "setTimeout(",
            "setInterval(",
        ]

        for indicator in execution_indicators:
            if indicator in response.lower():
                return True

        return False

    def _check_dom_vulnerability(self, response: str) -> bool:
        """
        Check for DOM-based XSS vulnerability.

        Args:
            response: Response text

        Returns:
            bool: True if DOM vulnerability detected
        """
        for indicator in self.DOM_INDICATORS:
            if indicator in response and re.search(
                r"(document\.|window\.|location\.)", response, re.IGNORECASE
            ):
                return True

        return False

    def _check_pattern_match(self, payload: str, response: str) -> bool:
        """
        Check if payload pattern matches in response.

        Args:
            payload: XSS payload
            response: Response text

        Returns:
            bool: True if pattern matches
        """
        # Extract script-like patterns from payload
        script_patterns = re.findall(r"<[^>]+>", payload)
        for pattern in script_patterns:
            if pattern in response:
                return True

        # Check for common XSS patterns
        xss_patterns = [
            r"<script",
            r"on\w+\s*=",
            r"javascript:",
            r"data:text/html",
        ]

        for pattern in xss_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True

        return False

    def _is_stored(self, response: str, payload: str) -> bool:
        """
        Check if XSS is stored (persistent).

        Args:
            response: Response text
            payload: XSS payload

        Returns:
            bool: True if stored
        """
        # Check if payload appears in multiple places or is persisted
        occurrences = response.count(payload)

        # If payload appears more than once, likely stored
        if occurrences > 2:
            return True

        # Check for database error indicators
        db_indicators = [
            "SQLite",
            "MySQL",
            "PostgreSQL",
            "ORA-",
            "database error",
            "SQL syntax",
        ]

        for indicator in db_indicators:
            if indicator in response:
                return True

        return False

    # ===========================================================
    # Finding Creation
    # ===========================================================

    def _create_xss_finding(
        self,
        url: str,
        parameter: str,
        payload: str,
        evidence: str,
        vulnerability_type: str,
        severity: str,
        confidence: float,
        status_code: int,
        response_time: float,
        description: str,
        remediation: str,
    ) -> None:
        """
        Create and add an XSS finding.

        Args:
            url: Vulnerable URL
            parameter: Vulnerable parameter
            payload: Payload used
            evidence: Evidence from response
            vulnerability_type: Type of vulnerability
            severity: Severity level
            confidence: Confidence score
            status_code: HTTP status code
            response_time: Response time
            description: Description
            remediation: Remediation steps
        """
        # Avoid duplicate findings
        for existing in self.findings:
            if (
                existing.url == url
                and existing.parameter == parameter
                and existing.vulnerability_type == vulnerability_type
            ):
                # Update confidence if higher
                existing.confidence = max(existing.confidence, confidence * 100)
                return

        finding = self.create_finding(
            vulnerability_type=vulnerability_type,
            severity=severity,
            description=description,
            confidence=confidence * 100,  # Convert to percentage
            url=url,
            method="GET",
            parameter=parameter,
            payload=payload,
            evidence=evidence[:500],
            remediation=remediation,
            status_code=status_code,
            response_time=response_time,
            tags=["xss", vulnerability_type.replace("_", "_")],
            metadata={
                "parameter": parameter,
                "payload": payload,
                "response_time": response_time,
                "status_code": status_code,
            },
        )

        self.add_finding(finding)
        self.logger.info(f"XSS finding: {severity} - {url} ({parameter})")

    # ===========================================================
    # Remediation
    # ===========================================================

    def _get_remediation(self, parameter: str) -> str:
        """
        Get remediation steps for XSS.

        Args:
            parameter: Vulnerable parameter

        Returns:
            str: Remediation steps
        """
        return f"""
1. Input Validation: Validate all input to the '{parameter}' parameter
2. Output Encoding: Encode output using HTML entity encoding
3. Use Context-Aware Encoding: Use appropriate encoding for the context
4. Content Security Policy: Implement CSP headers
5. Use X-XSS-Protection: Enable X-XSS-Protection header
6. Sanitize User Input: Use a whitelist of allowed characters
7. Use Parameterized Queries: For stored XSS prevention
        """.strip()

    def _get_dom_remediation(self) -> str:
        """
        Get remediation steps for DOM XSS.

        Returns:
            str: Remediation steps
        """
        return """
1. Avoid using eval(), setTimeout(), setInterval() with user input
2. Use innerText/textContent instead of innerHTML
3. Validate and sanitize input before using in DOM manipulation
4. Use DOMPurify or similar sanitization library
5. Implement Content Security Policy
6. Use JSON.parse() for JSON data
7. Avoid using document.write() with user input
        """.strip()

    # ===========================================================
    # Statistics
    # ===========================================================

    def get_statistics(self) -> dict[str, Any]:
        """
        Get XSS scanner statistics.

        Returns:
            dict[str, Any]: Statistics
        """
        stats = super().summary()

        xss_types = {
            "reflected": 0,
            "stored": 0,
            "dom": 0,
            "pattern": 0,
        }

        for finding in self.findings:
            vt = finding.vulnerability_type
            if "reflected" in vt:
                xss_types["reflected"] += 1
            elif "stored" in vt:
                xss_types["stored"] += 1
            elif "dom" in vt:
                xss_types["dom"] += 1
            else:
                xss_types["pattern"] += 1

        stats["xss_types"] = xss_types
        stats["payloads_tested"] = len(self.payloads)
        stats["parameters_tested"] = len(self._tested_params)
        stats["endpoints_tested"] = len(self._tested_endpoints)

        return stats


# ===========================================================
# Legacy Compatibility
# ===========================================================


class LegacyXSSScanner(XSSScanner):
    """
    Legacy XSSScanner for backward compatibility.

    This class maintains the old interface for existing tests.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger.warning("LegacyXSSScanner is deprecated. Use XSSScanner instead.")

    def scan(self) -> list[dict[str, Any]]:
        """
        Legacy scan method returning dictionaries.

        Returns:
            list[dict[str, Any]]: List of findings as dictionaries
        """
        results = self.run()
        return [r.to_dict() for r in results]


# ===========================================================
# Test Runner
# ===========================================================

if __name__ == "__main__":
    # Quick test
    scanner = XSSScanner("https://example.com/search?q=test")
    results = scanner.run()

    print("=" * 60)
    print("XSS Scanner Test")
    print("=" * 60)
    print(scanner.get_statistics())
    print()

    for result in results:
        print(result.get_summary())
        print(f"  Parameter: {result.parameter}")
        print(f"  Payload: {result.payload}")
        print(f"  Confidence: {result.confidence}%")
        print(f"  Evidence: {result.evidence[:100]}...")
        print()
