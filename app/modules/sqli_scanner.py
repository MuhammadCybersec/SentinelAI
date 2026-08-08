"""
SQL Injection Scanner - Production Grade
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

import requests

from app.modules.scanner.core.base_scanner import BaseScanner
from app.modules.scanner.core.request_engine import RequestEngine
from app.modules.scanner.core.response_analyzer import ResponseAnalyzer
from app.modules.scanner.findings.sql_finding import SQLFinding
from app.modules.scanner.payloads.sql_payloads import get_payloads
from app.modules.recon.scope_manager import ScopeManager


class SQLiScanner(BaseScanner):
    """
    Production SQL Injection Scanner.

    Features:
    - Only scans URLs with query parameters
    - Error-based detection with DBMS fingerprinting
    - Boolean-based detection
    - Time-based detection
    - False positive reduction
    - Confidence scoring
    """

    # SQL error patterns for DBMS fingerprinting
    DBMS_ERRORS: Dict[str, List[str]] = {
        "MySQL": [
            "you have an error in your sql syntax",
            "warning: mysql",
            "mysql_fetch",
            "mysql_num_rows",
            "mysql_affected_rows",
            "mysqli_error",
            "mysql_escape_string",
            "sql syntax.*mysql",
            "unclosed quotation mark",
            "unknown column",
            "duplicate entry",
        ],
        "PostgreSQL": [
            "postgresql",
            "pg_query",
            "pg_exec",
            "pg_fetch",
            "pg_numrows",
            "pg_affected_rows",
            "pg_last_error",
            "syntax error at or near",
            "relation .* does not exist",
            "column .* does not exist",
        ],
        "MSSQL": [
            "microsoft ole db provider for odbc drivers",
            "microsoft ole db provider for sql server",
            "sql server",
            "sqlserver",
            "unclosed quotation mark",
            "line .* syntax error",
            "invalid column name",
            "invalid object name",
            "could not find stored procedure",
        ],
        "Oracle": [
            "ora-",
            "oracle error",
            "oracle database",
            "oci error",
            "ora-00933",
            "ora-01756",
            "invalid identifier",
        ],
        "SQLite": [
            "sqlite",
            "sqlite3",
            "sqliteexception",
            "operationalerror",
            "no such table",
            "no such column",
        ],
    }

    # SQL error patterns (for detection)
    SQL_ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"warning:\s*mysql",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"mysql_affected_rows",
        r"mysqli_error",
        r"unclosed quotation mark",
        r"sql syntax",
        r"postgresql",
        r"pg_query",
        r"ora-",
        r"oracle error",
        r"sqlite",
        r"invalid query",
        r"database error",
    ]

    def __init__(
        self,
        target: str,
        scope: Optional[ScopeManager] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize SQL Injection Scanner."""
        super().__init__(target=target, scope=scope)
        self._config = config or {}
        self._request_engine = RequestEngine()
        self._analyzer = ResponseAnalyzer()
        self._session = requests.Session()
        self._logger = logging.getLogger(__name__)

        # Scanner state
        self._findings: List[SQLFinding] = []
        self._detected_dbms: Optional[str] = None
        self._baseline_response: Optional[requests.Response] = None
        self._baseline_time: Optional[float] = None

        # Statistics
        self.statistics = {
            "payloads_tested": 0,
            "requests_sent": 0,
            "vulnerabilities_found": 0,
            "errors": 0,
            "urls_skipped": 0,
        }

        # Configuration
        self.stop_on_first = False
        self.max_findings = 10
        self.time_threshold = 5.0
        self.timeout = 10
        self.min_confidence = 0.6
        self.request_delay = 0.1

        # Get payloads
        self._payloads = get_payloads()
        self._time_payloads = self._build_time_payloads()

    def _build_time_payloads(self) -> List[str]:
        """Build time-based payloads."""
        return [
            "' AND SLEEP(5)--",
            '" AND SLEEP(5)--',
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND DBMS_LOCK.SLEEP(5)--",
            "' AND pg_sleep(5)--",
        ]

    def _has_parameters(self, url: str) -> bool:
        """
        Check if URL has query parameters.

        Args:
            url: URL to check

        Returns:
            True if URL has parameters, False otherwise
        """
        parsed = urlparse(url)
        return bool(parsed.query)

    def _extract_parameters(self, url: str) -> Dict[str, List[str]]:
        """
        Extract query parameters from URL.

        Args:
            url: URL to parse

        Returns:
            Dictionary of parameter names to values
        """
        parsed = urlparse(url)
        return parse_qs(parsed.query)

    def _get_baseline(self, url: str) -> Optional[requests.Response]:
        """
        Get baseline response for comparison.

        Args:
            url: URL to request

        Returns:
            Response object or None
        """
        if self._baseline_response is None:
            try:
                start = perf_counter()
                response = self._session.get(url, timeout=self.timeout)
                self._baseline_time = perf_counter() - start
                self._baseline_response = response
                self._logger.debug(f"Baseline response: {response.status_code}")
                return response
            except Exception as e:
                self._logger.error(f"Baseline request failed: {e}")
                return None
        return self._baseline_response

    def _has_sql_error(self, response_text: str) -> tuple[bool, Optional[str]]:
        """
        Check if response contains SQL error.

        Args:
            response_text: Response body

        Returns:
            Tuple of (has_error, detected_dbms)
        """
        if not response_text:
            return False, None

        text = response_text.lower()

        # Check each DBMS pattern
        for dbms, patterns in self.DBMS_ERRORS.items():
            for pattern in patterns:
                if pattern in text:
                    return True, dbms

        # Check generic SQL error patterns
        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True, "Unknown"

        return False, None

    def _test_error_based(
        self, url: str, param: str, payload: str
    ) -> Optional[SQLFinding]:
        """
        Test error-based SQL injection.

        Args:
            url: Target URL
            param: Parameter to inject
            payload: Payload to test

        Returns:
            SQLFinding if vulnerability found, None otherwise
        """
        # Build test URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]

        from urllib.parse import urlencode, urlunparse

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

        try:
            self.statistics["requests_sent"] += 1
            response = self._session.get(test_url, timeout=self.timeout)

            # Check for SQL errors
            has_error, dbms = self._has_sql_error(response.text)

            if has_error:
                finding = SQLFinding()
                finding.vulnerable = True
                finding.url = url
                finding.parameter = param
                finding.payload = payload
                finding.technique = "Error-Based"
                finding.dbms = dbms or "Unknown"
                finding.confidence = 0.95
                finding.evidence = [
                    f"SQL error detected in parameter: {param}",
                    f"Payload: {payload}",
                    f"DBMS: {dbms or 'Unknown'}",
                    f"Status: {response.status_code}",
                ]
                finding.severity = "High"
                finding.cwe = "CWE-89"
                finding.description = f"SQL Injection vulnerability detected in parameter '{param}' using Error-Based technique"
                finding.remediation = "Use parameterized queries (Prepared Statements)"
                finding.references = [
                    "https://cwe.mitre.org/data/definitions/89.html",
                    "https://owasp.org/Top10/A03_2021-Injection/",
                ]
                finding.tags = ["sql_injection", "error_based", dbms or "unknown"]
                finding.metadata = {
                    "dbms": dbms,
                    "payload": payload,
                    "parameter": param,
                    "status_code": response.status_code,
                }

                self.statistics["vulnerabilities_found"] += 1
                self._detected_dbms = dbms
                return finding

        except Exception as e:
            self._logger.debug(f"Error testing {param} with {payload}: {e}")
            self.statistics["errors"] += 1

        return None

    def _test_boolean_based(self, url: str, param: str) -> Optional[SQLFinding]:
        """
        Test boolean-based SQL injection.

        Args:
            url: Target URL
            param: Parameter to test

        Returns:
            SQLFinding if vulnerability found, None otherwise
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        true_payload = "' AND 1=1--"
        false_payload = "' AND 1=2--"

        # Build test URLs
        from urllib.parse import urlencode, urlunparse

        true_params = params.copy()
        true_params[param] = [true_payload]
        true_query = urlencode(true_params, doseq=True)
        true_url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                true_query,
                parsed.fragment,
            )
        )

        false_params = params.copy()
        false_params[param] = [false_payload]
        false_query = urlencode(false_params, doseq=True)
        false_url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                false_query,
                parsed.fragment,
            )
        )

        try:
            self.statistics["requests_sent"] += 2
            true_response = self._session.get(true_url, timeout=self.timeout)
            false_response = self._session.get(false_url, timeout=self.timeout)

            # Compare responses
            true_length = len(true_response.text)
            false_length = len(false_response.text)
            diff = abs(true_length - false_length)

            # If responses are significantly different, boolean-based SQLi exists
            if diff > 50 or true_length == 0 or false_length == 0:
                finding = SQLFinding()
                finding.vulnerable = True
                finding.url = url
                finding.parameter = param
                finding.payload = true_payload
                finding.technique = "Boolean-Based"
                finding.dbms = self._detected_dbms or "Unknown"
                finding.confidence = 0.85
                finding.evidence = [
                    f"Boolean response difference detected in parameter: {param}",
                    f"True payload: {true_payload}",
                    f"False payload: {false_payload}",
                    f"Length difference: {diff} chars",
                ]
                finding.severity = "High"
                finding.cwe = "CWE-89"
                finding.description = (
                    f"Boolean-based SQL Injection detected in parameter '{param}'"
                )
                finding.remediation = "Use parameterized queries (Prepared Statements)"
                finding.references = [
                    "https://cwe.mitre.org/data/definitions/89.html",
                    "https://owasp.org/Top10/A03_2021-Injection/",
                ]
                finding.tags = ["sql_injection", "boolean_based"]
                finding.metadata = {
                    "true_payload": true_payload,
                    "false_payload": false_payload,
                    "length_difference": diff,
                    "parameter": param,
                }

                self.statistics["vulnerabilities_found"] += 1
                return finding

        except Exception as e:
            self._logger.debug(f"Boolean test failed for {param}: {e}")
            self.statistics["errors"] += 1

        return None

    def _test_time_based(
        self, url: str, param: str, payload: str
    ) -> Optional[SQLFinding]:
        """
        Test time-based SQL injection.

        Args:
            url: Target URL
            param: Parameter to inject
            payload: Time-based payload

        Returns:
            SQLFinding if vulnerability found, None otherwise
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]

        from urllib.parse import urlencode, urlunparse

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

        try:
            self.statistics["requests_sent"] += 1
            start = perf_counter()
            response = self._session.get(test_url, timeout=self.timeout + 2)
            elapsed = perf_counter() - start

            # Compare with baseline
            if (
                self._baseline_time
                and elapsed - self._baseline_time > self.time_threshold
            ):
                finding = SQLFinding()
                finding.vulnerable = True
                finding.url = url
                finding.parameter = param
                finding.payload = payload
                finding.technique = "Time-Based"
                finding.dbms = self._detected_dbms or "Unknown"
                finding.confidence = 0.90
                finding.evidence = [
                    f"Time-based delay detected in parameter: {param}",
                    f"Payload: {payload}",
                    f"Delay: {elapsed - self._baseline_time:.2f}s",
                    f"Baseline: {self._baseline_time:.2f}s",
                ]
                finding.severity = "High"
                finding.cwe = "CWE-89"
                finding.description = (
                    f"Time-based SQL Injection detected in parameter '{param}'"
                )
                finding.remediation = "Use parameterized queries (Prepared Statements)"
                finding.references = [
                    "https://cwe.mitre.org/data/definitions/89.html",
                    "https://owasp.org/Top10/A03_2021-Injection/",
                ]
                finding.tags = ["sql_injection", "time_based"]
                finding.metadata = {
                    "payload": payload,
                    "delay": elapsed - self._baseline_time,
                    "baseline": self._baseline_time,
                    "parameter": param,
                }

                self.statistics["vulnerabilities_found"] += 1
                return finding

        except Exception as e:
            self._logger.debug(f"Time test failed for {param}: {e}")
            self.statistics["errors"] += 1

        return None

    def _get_smart_payloads(self) -> List[str]:
        """
        Get payloads optimized for detected DBMS.

        Returns:
            List of payload strings
        """
        if self._detected_dbms == "MySQL":
            return [
                p
                for p in self._payloads
                if "sleep" in p.lower() or "benchmark" in p.lower()
            ]
        elif self._detected_dbms == "PostgreSQL":
            return [p for p in self._payloads if "pg_sleep" in p.lower()]
        elif self._detected_dbms == "MSSQL":
            return [p for p in self._payloads if "waitfor" in p.lower()]
        else:
            return self._payloads[:50]  # Limit payloads

    def scan(self, session: Optional[requests.Session] = None) -> List[SQLFinding]:
        """
        Execute SQL Injection scan.

        Args:
            session: Optional authenticated session

        Returns:
            List of SQLFinding objects
        """
        self._findings = []
        self.statistics["payloads_tested"] = 0
        self.statistics["requests_sent"] = 0
        self.statistics["vulnerabilities_found"] = 0
        self.statistics["errors"] = 0
        self.statistics["urls_skipped"] = 0

        if session:
            self._session = session

        # Step 1: Check if URL has parameters
        if not self._has_parameters(self.target):
            self._logger.debug(f"Skipping {self.target} - no query parameters")
            self.statistics["urls_skipped"] += 1
            return []

        # Step 2: Get baseline response
        baseline = self._get_baseline(self.target)
        if not baseline:
            self._logger.warning(f"Baseline request failed for {self.target}")
            return []

        # Step 3: Check if baseline already has SQL errors
        has_error, dbms = self._has_sql_error(baseline.text)
        if has_error:
            self._detected_dbms = dbms
            self._logger.info(f"SQL error detected in baseline: {dbms}")

        # Step 4: Extract parameters
        params = self._extract_parameters(self.target)
        if not params:
            return []

        # Step 5: Get payloads
        payloads = self._get_smart_payloads()
        self._logger.info(
            f"Testing {len(payloads)} payloads on {len(params)} parameters"
        )

        # Step 6: Test each parameter
        for param_name in params.keys():
            if len(self._findings) >= self.max_findings:
                break

            self._logger.debug(f"Testing parameter: {param_name}")

            # Test error-based
            for payload in payloads[:20]:  # Limit error-based payloads
                if self.stop_on_first and self._findings:
                    break

                self.statistics["payloads_tested"] += 1
                finding = self._test_error_based(self.target, param_name, payload)
                if finding:
                    self._findings.append(finding)
                    self._logger.info(
                        f"Found SQL injection: {param_name} ({finding.technique})"
                    )
                    break

            # Test boolean-based
            if not self._findings or not self.stop_on_first:
                finding = self._test_boolean_based(self.target, param_name)
                if finding:
                    self._findings.append(finding)
                    self._logger.info(
                        f"Found SQL injection: {param_name} ({finding.technique})"
                    )

            # Test time-based
            if not self._findings or not self.stop_on_first:
                for payload in self._time_payloads[:3]:
                    if self.stop_on_first and self._findings:
                        break

                    self.statistics["payloads_tested"] += 1
                    finding = self._test_time_based(self.target, param_name, payload)
                    if finding:
                        self._findings.append(finding)
                        self._logger.info(
                            f"Found SQL injection: {param_name} ({finding.technique})"
                        )
                        break

        self._logger.info(f"Scan complete: {len(self._findings)} findings found")
        return self._findings

    def get_findings(self) -> List[SQLFinding]:
        """Get scan findings."""
        return self._findings.copy()

    def get_statistics(self) -> Dict[str, Any]:
        """Get scan statistics."""
        return self.statistics.copy()

    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary."""
        return {
            "target": self.target,
            "total_findings": len(self._findings),
            "payloads_tested": self.statistics["payloads_tested"],
            "requests_sent": self.statistics["requests_sent"],
            "errors": self.statistics["errors"],
            "urls_skipped": self.statistics["urls_skipped"],
            "dbms": self._detected_dbms,
            "findings": [
                {
                    "parameter": f.parameter,
                    "technique": f.technique,
                    "dbms": f.dbms,
                    "confidence": f.confidence,
                }
                for f in self._findings
            ],
        }
