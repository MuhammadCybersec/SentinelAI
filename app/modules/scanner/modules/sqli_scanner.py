"""
SQL Injection Scanner - Production Grade v3
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from time import perf_counter
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

import requests

from app.modules.scanner.core.base_scanner import BaseScanner
from app.modules.recon.scope_manager import ScopeManager


class SQLiScanner(BaseScanner):
    """
    Production SQL Injection Scanner with strict URL validation.
    """

    SQL_ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"mysql_fetch",
        r"warning:\s*mysql",
        r"unclosed quotation mark",
        r"sqlstate",
        r"mysql_num_rows",
        r"mysqli_error",
        r"ora-\d{5}",
        r"oracle error",
        r"postgresql",
        r"pg_query",
        r"sqlite3\.OperationalError",
        r"SQL syntax.*near",
        r"Unknown column",
        r"Table '.*' doesn't exist",
    ]

    DBMS_ERRORS: Dict[str, List[str]] = {
        "MySQL": [
            "you have an error in your sql syntax",
            "mysql_fetch",
            "mysql_num_rows",
            "mysqli_error",
            "sqlstate",
            "Unknown column",
            "Table '.*' doesn't exist",
        ],
        "PostgreSQL": ["postgresql", "pg_query", "sqlstate"],
        "MSSQL": ["sql server", "unclosed quotation mark", "sqlstate"],
        "Oracle": ["ora-", "oracle error"],
        "SQLite": ["sqlite3.OperationalError", "sqlite"],
    }

    def __init__(
        self,
        target: str,
        scope: Optional[ScopeManager] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(target=target, scope=scope)
        self.scanner_name = "sqli"
        self.scanner_version = "3.0.0"
        self._config = config or {}
        self._session = requests.Session()
        self._logger = logging.getLogger(__name__)

        self._findings: List[Dict[str, Any]] = []
        self._detected_dbms: Optional[str] = None
        self._baseline_response: Optional[requests.Response] = None
        self._baseline_time: Optional[float] = None
        self._project_id: Optional[str] = None

        self.statistics = {
            "payloads_tested": 0,
            "requests_sent": 0,
            "vulnerabilities_found": 0,
            "errors": 0,
            "urls_skipped": 0,
            "urls_scanned": 0,
        }

        self.stop_on_first = True
        self.max_findings = 5
        self.time_threshold = 5.0
        self.timeout = 10
        self.min_confidence = 0.8

        self._payloads = self._get_effective_payloads()
        self._time_payloads = self._build_time_payloads()

        self._load_project_id()

    def _get_effective_payloads(self) -> List[str]:
        return [
            "' OR '1'='1",
            "' OR 1=1--",
            "' AND 1=1--",
            "' AND 1=2--",
            "' UNION SELECT NULL--",
            "' OR SLEEP(5)--",
            "' AND SLEEP(5)--",
            "1' AND '1'='1",
            "1' AND '1'='2",
        ]

    def _build_time_payloads(self) -> List[str]:
        return [
            "' AND SLEEP(5)--",
            '" AND SLEEP(5)--',
            "'; WAITFOR DELAY '0:0:5'--",
        ]

    def _load_project_id(self) -> None:
        try:
            from app.database.session import SessionLocal
            from app.database.models.project import Project

            db = SessionLocal()
            try:
                project = (
                    db.query(Project)
                    .filter(Project.target.like(f"%{self.target}%"))
                    .first()
                )
                if project:
                    self._project_id = project.id
                    self._logger.debug(f"Loaded project_id: {self._project_id}")
            finally:
                db.close()
        except Exception as e:
            self._logger.debug(f"Could not load project_id: {e}")

    def _is_valid_target(self, url: str) -> bool:
        parsed = urlparse(url)
        query = parsed.query

        if not query:
            self._logger.debug(f"Skipping {url} - no query parameters")
            return False

        if "=" not in query:
            self._logger.debug(f"Skipping {url} - no '=' in query")
            return False

        params = parse_qs(query)
        has_value = any(v and v[0] for v in params.values())
        if not has_value:
            self._logger.debug(f"Skipping {url} - all parameters empty")
            return False

        self._logger.debug(f"✅ Valid target: {url}")
        return True

    def _has_sql_error(self, response_text: str) -> tuple[bool, Optional[str]]:
        if not response_text:
            return False, None

        text = response_text.lower()

        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                for dbms, patterns in self.DBMS_ERRORS.items():
                    for dbms_pattern in patterns:
                        if re.search(dbms_pattern, text, re.IGNORECASE):
                            return True, dbms
                return True, "Unknown"

        return False, None

    def _get_baseline(self, url: str) -> Optional[requests.Response]:
        if self._baseline_response is None:
            try:
                start = perf_counter()
                response = self._session.get(url, timeout=self.timeout)
                self._baseline_time = perf_counter() - start
                self._baseline_response = response
                self._logger.debug(
                    f"Baseline: {response.status_code}, {len(response.text)} chars"
                )
                return response
            except Exception as e:
                self._logger.error(f"Baseline failed: {e}")
                return None
        return self._baseline_response

    def _test_error_based(
        self, url: str, param: str, payload: str
    ) -> Optional[Dict[str, Any]]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]

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

            has_error, dbms = self._has_sql_error(response.text)

            if has_error and self._baseline_response:
                baseline_has_error, _ = self._has_sql_error(
                    self._baseline_response.text
                )
                if baseline_has_error:
                    return None

                baseline_len = len(self._baseline_response.text)
                response_len = len(response.text)
                diff = abs(response_len - baseline_len)

                if diff < 50:
                    return None

                return {
                    "vulnerability_type": "SQL Injection",
                    "severity": "High",
                    "title": f"SQL Injection in {param}",
                    "description": f"Error-based SQL Injection in parameter '{param}'",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"SQL error: {dbms or 'Unknown'}, length diff: {diff}",
                    "recommendation": "Use parameterized queries (Prepared Statements)",
                    "cwe": "CWE-89",
                    "owasp": "A03:2021 - Injection",
                    "confidence": 0.95,
                    "tags": ["sql_injection", "error_based"],
                    "metadata": {
                        "dbms": dbms,
                        "payload": payload,
                        "parameter": param,
                        "length_difference": diff,
                    },
                    "scanner_name": self.scanner_name,
                    "scanner_version": self.scanner_version,
                    "method": "GET",
                    "status_code": response.status_code,
                    "response_time": 0.0,
                }

        except Exception as e:
            self._logger.debug(f"Error testing {param}: {e}")

        return None

    def _test_boolean_based(self, url: str, param: str) -> Optional[Dict[str, Any]]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        true_payload = "' AND 1=1--"
        false_payload = "' AND 1=2--"

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

            baseline = self._get_baseline(url)
            if not baseline:
                return None

            true_response = self._session.get(true_url, timeout=self.timeout)
            false_response = self._session.get(false_url, timeout=self.timeout)

            true_len = len(true_response.text)
            false_len = len(false_response.text)
            baseline_len = len(baseline.text)

            diff = abs(true_len - false_len)
            baseline_diff = abs(true_len - baseline_len)

            if diff > 100 and baseline_diff > 50:
                return {
                    "vulnerability_type": "SQL Injection",
                    "severity": "High",
                    "title": f"Boolean SQL Injection in {param}",
                    "description": f"Boolean-based SQL Injection in parameter '{param}'",
                    "url": url,
                    "parameter": param,
                    "payload": true_payload,
                    "evidence": f"Length diff: {diff}, true: {true_len}, false: {false_len}",
                    "recommendation": "Use parameterized queries (Prepared Statements)",
                    "cwe": "CWE-89",
                    "owasp": "A03:2021 - Injection",
                    "confidence": 0.85,
                    "tags": ["sql_injection", "boolean_based"],
                    "metadata": {
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "length_difference": diff,
                        "parameter": param,
                    },
                    "scanner_name": self.scanner_name,
                    "scanner_version": self.scanner_version,
                    "method": "GET",
                    "status_code": 200,
                    "response_time": 0.0,
                }

        except Exception as e:
            self._logger.debug(f"Boolean test failed: {e}")

        return None

    def _test_time_based(
        self, url: str, param: str, payload: str
    ) -> Optional[Dict[str, Any]]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]

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

            if self._baseline_time is None:
                self._get_baseline(url)
                if self._baseline_time is None:
                    return None

            start = perf_counter()
            response = self._session.get(test_url, timeout=self.timeout + 2)
            elapsed = perf_counter() - start

            if (
                self._baseline_time
                and elapsed - self._baseline_time > self.time_threshold
                and elapsed > 5.0
            ):
                return {
                    "vulnerability_type": "SQL Injection",
                    "severity": "High",
                    "title": f"Time-based SQL Injection in {param}",
                    "description": f"Time-based SQL Injection in parameter '{param}'",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"Delay: {elapsed - self._baseline_time:.2f}s",
                    "recommendation": "Use parameterized queries (Prepared Statements)",
                    "cwe": "CWE-89",
                    "owasp": "A03:2021 - Injection",
                    "confidence": 0.90,
                    "tags": ["sql_injection", "time_based"],
                    "metadata": {
                        "payload": payload,
                        "delay": elapsed - self._baseline_time,
                        "baseline": self._baseline_time,
                        "parameter": param,
                    },
                    "scanner_name": self.scanner_name,
                    "scanner_version": self.scanner_version,
                    "method": "GET",
                    "status_code": 200,
                    "response_time": elapsed - self._baseline_time,
                }

        except Exception as e:
            self._logger.debug(f"Time test failed: {e}")

        return None

    def _store_finding(self, finding_data: Dict[str, Any]) -> bool:
        try:
            from app.database.session import SessionLocal
            from app.database.models.finding import Finding

            if not self._project_id:
                self._logger.warning("No project_id, cannot store finding")
                return False

            db = SessionLocal()
            try:
                db_finding = Finding(
                    id=str(uuid.uuid4()),
                    project_id=self._project_id,
                    title=finding_data.get("title", "SQL Injection"),
                    description=finding_data.get("description", ""),
                    severity=finding_data.get("severity", "High"),
                    cvss=7.5,
                    status="Open",
                    module="sqli_scanner",
                    target=self.target,
                    vulnerability_type=finding_data.get(
                        "vulnerability_type", "SQL Injection"
                    ),
                    scanner_name=finding_data.get("scanner_name", self.scanner_name),
                    scanner_version=finding_data.get(
                        "scanner_version", self.scanner_version
                    ),
                    url=finding_data.get("url", self.target),
                    method=finding_data.get("method", "GET"),
                    parameter=finding_data.get("parameter", ""),
                    payload=finding_data.get("payload", ""),
                    status_code=finding_data.get("status_code", 0),
                    response_time=finding_data.get("response_time", 0.0),
                    evidence=finding_data.get("evidence", ""),
                    recommendation=finding_data.get("recommendation", ""),
                    reference="",
                    confidence=finding_data.get("confidence", 0.9),
                    is_false_positive=False,
                    verified=False,
                    cwe=finding_data.get("cwe", "CWE-89"),
                    owasp=finding_data.get("owasp", "A03:2021 - Injection"),
                    tags=",".join(finding_data.get("tags", [])),
                    metadata_json=json.dumps(finding_data.get("metadata", {})),
                )

                db.add(db_finding)
                db.commit()
                self.statistics["vulnerabilities_found"] += 1
                self._logger.info(f"✅ Finding stored: {db_finding.id[:8]}")
                return True

            except Exception as e:
                db.rollback()
                self._logger.error(f"DB error: {e}")
                return False
            finally:
                db.close()

        except Exception as e:
            self._logger.error(f"Store error: {e}")
            return False

    def scan(self, session: Optional[requests.Session] = None) -> List[Dict[str, Any]]:
        self._findings = []
        self.statistics = {k: 0 for k in self.statistics}

        if session:
            self._session = session

        if not self._is_valid_target(self.target):
            self._logger.info(f"⏭️ Skipping {self.target}")
            self.statistics["urls_skipped"] += 1
            return []

        self.statistics["urls_scanned"] += 1

        baseline = self._get_baseline(self.target)
        if not baseline:
            self._logger.warning(f"Baseline failed for {self.target}")
            return []

        has_error, dbms = self._has_sql_error(baseline.text)
        if has_error:
            self._logger.warning(f"Baseline has SQL errors, skipping")
            return []

        params = parse_qs(urlparse(self.target).query)
        if not params:
            return []

        self._logger.info(f"🔍 Testing {len(params)} parameters on {self.target}")

        for param_name in params.keys():
            if len(self._findings) >= self.max_findings:
                break

            if not params[param_name] or not params[param_name][0]:
                continue

            self._logger.debug(f"Testing parameter: {param_name}")
            param_found = False

            for payload in self._payloads[:8]:
                if self.stop_on_first and param_found:
                    break
                self.statistics["payloads_tested"] += 1
                finding = self._test_error_based(self.target, param_name, payload)
                if finding:
                    self._findings.append(finding)
                    param_found = True
                    self._logger.info(f"✅ Found SQLi: {param_name} (Error-Based)")
                    self._store_finding(finding)
                    break

            if not param_found:
                finding = self._test_boolean_based(self.target, param_name)
                if finding:
                    self._findings.append(finding)
                    param_found = True
                    self._logger.info(f"✅ Found SQLi: {param_name} (Boolean-Based)")
                    self._store_finding(finding)

            if not param_found:
                for payload in self._time_payloads[:2]:
                    if self.stop_on_first and param_found:
                        break
                    self.statistics["payloads_tested"] += 1
                    finding = self._test_time_based(self.target, param_name, payload)
                    if finding:
                        self._findings.append(finding)
                        param_found = True
                        self._logger.info(f"✅ Found SQLi: {param_name} (Time-Based)")
                        self._store_finding(finding)
                        break

        self._logger.info(f"📊 Scan complete: {len(self._findings)} findings")
        return self._findings

    def get_findings(self) -> List[Dict[str, Any]]:
        return self._findings.copy()

    def get_statistics(self) -> Dict[str, Any]:
        return self.statistics.copy()
