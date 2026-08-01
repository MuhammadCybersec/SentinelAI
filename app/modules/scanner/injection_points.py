# app/modules/scanner/injection_points.py
"""
Intelligent Injection Point Discovery for SentinelAI.
Phase 8: Discovers all potential injection points in requests.
"""

import json
import logging
import re
import time  # ADDED
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests

from .html_parser import HTMLParser
from .regex_utils import RegexUtils
from .union_sqli import UnionSQLi

# ============================================================
# Data Classes
# ============================================================


@dataclass
class InjectionPointResult:
    """
    Injection point discovery result.
    Represents a single potential injection point.
    """

    parameter_name: str = ""
    parameter_type: str = ""  # GET, POST, JSON, XML, COOKIE, HEADER
    original_value: str = ""
    test_value: str = ""
    is_injectable: bool = False
    confidence: int = 0
    risk_level: str = "LOW"
    evidence: list[str] = field(default_factory=list)
    reason: str = ""
    location: str = ""  # Full path or location
    value_type: str = ""  # string, number, boolean, array, object, null

    def add_evidence(self, evidence: str):
        """Add evidence to the result."""
        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)

    def get_summary(self) -> str:
        """Get a summary of the injection point."""
        if self.is_injectable:
            status = "INJECTABLE"
        else:
            status = "Not injectable"

        return f"{self.parameter_type}::{self.parameter_name} = {self.original_value} [{status}] Confidence: {self.confidence}%"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "parameter_name": self.parameter_name,
            "parameter_type": self.parameter_type,
            "original_value": self.original_value,
            "test_value": self.test_value,
            "is_injectable": self.is_injectable,
            "confidence": self.confidence,
            "risk_level": self.risk_level,
            "evidence": self.evidence,
            "reason": self.reason,
            "location": self.location,
            "value_type": self.value_type,
            "summary": self.get_summary(),
        }


@dataclass
class InjectionDiscoveryResult:
    """
    Complete injection point discovery result.
    Contains all discovered injection points.
    """

    success: bool = False
    parameters: list[InjectionPointResult] = field(default_factory=list)
    total_parameters: int = 0
    injectable_parameters: int = 0
    errors: list[str] = field(default_factory=list)
    execution_time: float = 0.0

    def add_parameter(self, param: InjectionPointResult):
        """Add a parameter to the result."""
        self.parameters.append(param)
        self.total_parameters += 1
        if param.is_injectable:
            self.injectable_parameters += 1

    def add_error(self, error: str):
        """Add an error to the result."""
        self.errors.append(error)

    def get_best_parameter(self) -> InjectionPointResult | None:
        """
        Get the best injection point (highest confidence).

        Returns:
            Optional[InjectionPointResult]: Best parameter or None
        """
        if not self.parameters:
            return None

        injectable = [p for p in self.parameters if p.is_injectable]
        if injectable:
            return max(injectable, key=lambda x: x.confidence)

        return max(self.parameters, key=lambda x: x.confidence)

    def get_injectable_parameters(self) -> list[InjectionPointResult]:
        """Get all injectable parameters."""
        return [p for p in self.parameters if p.is_injectable]

    def count_parameters(self) -> int:
        """Get total number of parameters."""
        return self.total_parameters

    def count_injectable(self) -> int:
        """Get number of injectable parameters."""
        return self.injectable_parameters

    def get_summary(self) -> str:
        """Get a summary of the discovery result."""
        if not self.success:
            return "Parameter discovery failed"

        parts = []
        parts.append(f"Total parameters: {self.total_parameters}")
        parts.append(f"Injectable: {self.injectable_parameters}")

        if self.errors:
            parts.append(f"Errors: {len(self.errors)}")

        best = self.get_best_parameter()
        if best:
            parts.append(f"Best: {best.get_summary()}")

        return f"Discovery: {', '.join(parts)}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/output."""
        best = self.get_best_parameter()
        return {
            "success": self.success,
            "parameters": [p.to_dict() for p in self.parameters],
            "total_parameters": self.total_parameters,
            "injectable_parameters": self.injectable_parameters,
            "errors": self.errors,
            "execution_time": self.execution_time,
            "best_parameter": best.to_dict() if best else None,
            "summary": self.get_summary(),
        }


# ============================================================
# Main Injection Point Discovery Class
# ============================================================


class InjectionPointDiscovery:
    """
    Intelligent Injection Point Discovery engine.
    Phase 8: Discovers all potential injection points in requests.
    """

    # ============================================================
    # Constants
    # ============================================================

    # Parameter types
    PARAM_TYPE_GET = "GET"
    PARAM_TYPE_POST = "POST"
    PARAM_TYPE_JSON = "JSON"
    PARAM_TYPE_XML = "XML"
    PARAM_TYPE_COOKIE = "COOKIE"
    PARAM_TYPE_HEADER = "HEADER"

    # Risk levels
    RISK_CRITICAL = "CRITICAL"
    RISK_HIGH = "HIGH"
    RISK_MEDIUM = "MEDIUM"
    RISK_LOW = "LOW"

    # Test values for injection detection
    TEST_VALUES = [
        ("'", "Single quote"),
        ('"', "Double quote"),
        ("' OR '1'='1", "OR True"),
        ("' AND '1'='1", "AND True"),
        ("' AND '1'='2", "AND False"),
        ("' UNION SELECT NULL--", "UNION NULL"),
        ("admin'--", "SQL comment"),
        ("' OR 1=1--", "OR 1=1"),
    ]

    # Default suspicious parameters
    SUSPICIOUS_PARAMETERS = [
        "id",
        "user",
        "username",
        "login",
        "password",
        "pass",
        "email",
        "name",
        "search",
        "query",
        "q",
        "cat",
        "category",
        "page",
        "p",
        "sort",
        "order",
        "limit",
        "offset",
        "type",
        "mode",
        "action",
        "file",
        "filename",
        "path",
        "dir",
        "folder",
        "lang",
        "language",
        "country",
        "city",
        "state",
        "zip",
        "postal",
        "phone",
        "mobile",
        "age",
        "gender",
        "dob",
        "date",
        "time",
        "year",
        "month",
        "day",
        "url",
        "link",
        "ref",
        "referer",
        "source",
        "target",
        "dest",
        "data",
        "info",
        "text",
        "content",
        "message",
        "comment",
        "note",
        "token",
        "csrf",
        "auth",
        "api",
        "key",
        "secret",
        "hash",
        "md5",
        "sha1",
        "sha256",
        "uuid",
        "guid",
        "code",
        "code",
        "format",
        "callback",
        "jsonp",
        "cors",
        "origin",
        "host",
        "domain",
        "site",
    ]

    # ============================================================
    # Initialization
    # ============================================================

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        logger: logging.Logger | None = None,
    ):
        """
        Initialize Injection Point Discovery module.

        Args:
            session: Requests session for HTTP requests
            base_url: Target base URL
            logger: Optional logger instance
        """
        self.session = session
        self.base_url = base_url
        self.logger = logger or self._setup_logger()

        # Initialize components
        self.union_sqli = UnionSQLi(session, base_url, logger)
        self.html_parser = HTMLParser()
        self.regex_utils = RegexUtils()

        # State
        self.discovery_result = None

        self.logger.info(
            "[InjectionDiscovery] Module initialized for parameter discovery"
        )
        self.logger.info(f"[InjectionDiscovery] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("InjectionDiscovery")
        logger.setLevel(logging.DEBUG)

        if not logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            ch.setFormatter(formatter)
            logger.addHandler(ch)

        return logger

    # ============================================================
    # Private Methods
    # ============================================================

    def _get_parameter_type(self, value: Any) -> str:
        """Detect the type of a parameter value."""
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "number"
        if isinstance(value, float):
            return "number"
        if isinstance(value, dict):
            return "object"
        if isinstance(value, list):
            return "array"
        if isinstance(value, str):
            if value.isdigit():
                return "number"
            if value.lower() in ["true", "false"]:
                return "boolean"
            return "string"
        return "unknown"

    def _get_risk_level(self, confidence: int) -> str:
        """Get risk level based on confidence."""
        if confidence >= 80:
            return self.RISK_CRITICAL
        elif confidence >= 60:
            return self.RISK_HIGH
        elif confidence >= 40:
            return self.RISK_MEDIUM
        else:
            return self.RISK_LOW

    def _is_suspicious(self, param_name: str) -> bool:
        """Check if a parameter name is suspicious."""
        param_lower = param_name.lower()
        for suspicious in self.SUSPICIOUS_PARAMETERS:
            if suspicious in param_lower:
                return True
        return False

    def _calculate_confidence(self, param_name: str, param_type: str) -> int:
        """Calculate confidence score for a parameter."""
        confidence = 0

        # Suspicious parameter name
        if self._is_suspicious(param_name):
            confidence += 20

        # Parameter type priority
        priority = {
            self.PARAM_TYPE_GET: 10,
            self.PARAM_TYPE_POST: 15,
            self.PARAM_TYPE_JSON: 20,
            self.PARAM_TYPE_XML: 15,
            self.PARAM_TYPE_COOKIE: 5,
            self.PARAM_TYPE_HEADER: 5,
        }
        confidence += priority.get(param_type, 0)

        # Parameter length (longer = more likely injectable)
        if len(param_name) > 3:
            confidence += 5
        if len(param_name) > 10:
            confidence += 5

        return min(confidence, 100)

    # ============================================================
    # Public Discovery Methods
    # ============================================================

    def discover_get_parameters(self, url: str) -> list[InjectionPointResult]:
        """
        Discover GET parameters from URL.

        Args:
            url: URL to parse

        Returns:
            List[InjectionPointResult]: Discovered parameters
        """
        self.logger.info("[InjectionDiscovery] Discovering GET parameters...")

        results = []

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name, values in params.items():
                original_value = values[0] if values else ""

                result = InjectionPointResult(
                    parameter_name=param_name,
                    parameter_type=self.PARAM_TYPE_GET,
                    original_value=original_value,
                    test_value=original_value,
                    location=url,
                    value_type=self._get_parameter_type(original_value),
                )

                # Calculate confidence
                result.confidence = self._calculate_confidence(
                    param_name, self.PARAM_TYPE_GET
                )
                result.risk_level = self._get_risk_level(result.confidence)

                results.append(result)
                self.logger.debug(
                    f"[InjectionDiscovery] Found GET param: {param_name}={original_value}"
                )

        except Exception as e:
            self.logger.warning(
                f"[InjectionDiscovery] Failed to parse GET parameters: {e!s}"
            )

        self.logger.info(f"[InjectionDiscovery] Found {len(results)} GET parameters")
        return results

    def discover_post_parameters(self, data: str | dict) -> list[InjectionPointResult]:
        """
        Discover POST parameters from form data.

        Args:
            data: POST data (string or dict)

        Returns:
            List[InjectionPointResult]: Discovered parameters
        """
        self.logger.info("[InjectionDiscovery] Discovering POST parameters...")

        results = []

        try:
            if isinstance(data, str):
                # Parse URL encoded form data
                params = parse_qs(data)
            elif isinstance(data, dict):
                params = {
                    k: [v] if not isinstance(v, list) else v for k, v in data.items()
                }
            else:
                return results

            for param_name, values in params.items():
                original_value = values[0] if values else ""

                result = InjectionPointResult(
                    parameter_name=param_name,
                    parameter_type=self.PARAM_TYPE_POST,
                    original_value=original_value,
                    test_value=original_value,
                    location=self.base_url,
                    value_type=self._get_parameter_type(original_value),
                )

                result.confidence = self._calculate_confidence(
                    param_name, self.PARAM_TYPE_POST
                )
                result.risk_level = self._get_risk_level(result.confidence)

                results.append(result)
                self.logger.debug(
                    f"[InjectionDiscovery] Found POST param: {param_name}={original_value}"
                )

        except Exception as e:
            self.logger.warning(
                f"[InjectionDiscovery] Failed to parse POST parameters: {e!s}"
            )

        self.logger.info(f"[InjectionDiscovery] Found {len(results)} POST parameters")
        return results

    def discover_json_parameters(
        self, data: str | dict, prefix: str = ""
    ) -> list[InjectionPointResult]:
        """
        Discover parameters from JSON data (supports nested objects).

        Args:
            data: JSON data (string or dict)
            prefix: Prefix for nested parameters

        Returns:
            List[InjectionPointResult]: Discovered parameters
        """
        self.logger.info("[InjectionDiscovery] Discovering JSON parameters...")

        results = []

        try:
            if isinstance(data, str):
                parsed = json.loads(data)
            else:
                parsed = data

            self._discover_json_recursive(parsed, prefix, results)

        except Exception as e:
            self.logger.warning(f"[InjectionDiscovery] Failed to parse JSON: {e!s}")

        self.logger.info(f"[InjectionDiscovery] Found {len(results)} JSON parameters")
        return results

    def _discover_json_recursive(
        self, obj: Any, prefix: str, results: list[InjectionPointResult]
    ):
        """
        Recursively discover parameters in JSON objects.

        Args:
            obj: JSON object or array
            prefix: Prefix for nested parameters
            results: List to append results to
        """
        if isinstance(obj, dict):
            for key, value in obj.items():
                param_name = f"{prefix}.{key}" if prefix else key

                if isinstance(value, (dict, list)):
                    self._discover_json_recursive(value, param_name, results)
                else:
                    result = InjectionPointResult(
                        parameter_name=param_name,
                        parameter_type=self.PARAM_TYPE_JSON,
                        original_value=str(value) if value is not None else "null",
                        test_value=str(value) if value is not None else "null",
                        location=self.base_url,
                        value_type=self._get_parameter_type(value),
                    )
                    result.confidence = self._calculate_confidence(
                        param_name, self.PARAM_TYPE_JSON
                    )
                    result.risk_level = self._get_risk_level(result.confidence)
                    results.append(result)

        elif isinstance(obj, list):
            for idx, value in enumerate(obj):
                if prefix:
                    param_name = f"{prefix}[{idx}]"
                else:
                    param_name = f"[{idx}]"

                if isinstance(value, (dict, list)):
                    self._discover_json_recursive(value, param_name, results)
                else:
                    result = InjectionPointResult(
                        parameter_name=param_name,
                        parameter_type=self.PARAM_TYPE_JSON,
                        original_value=str(value) if value is not None else "null",
                        test_value=str(value) if value is not None else "null",
                        location=self.base_url,
                        value_type=self._get_parameter_type(value),
                    )
                    result.confidence = self._calculate_confidence(
                        param_name, self.PARAM_TYPE_JSON
                    )
                    result.risk_level = self._get_risk_level(result.confidence)
                    results.append(result)

    def discover_xml_parameters(self, data: str) -> list[InjectionPointResult]:
        """
        Discover parameters from XML data (supports nested elements).

        Args:
            data: XML string

        Returns:
            List[InjectionPointResult]: Discovered parameters
        """
        self.logger.info("[InjectionDiscovery] Discovering XML parameters...")

        results = []

        try:
            root = ET.fromstring(data)
            self._discover_xml_recursive(root, "", results)

        except ET.ParseError as e:
            self.logger.warning(f"[InjectionDiscovery] Failed to parse XML: {e!s}")

        self.logger.info(f"[InjectionDiscovery] Found {len(results)} XML parameters")
        return results

    def _discover_xml_recursive(
        self, element: ET.Element, prefix: str, results: list[InjectionPointResult]
    ):
        """
        Recursively discover parameters in XML elements.

        Args:
            element: XML element
            prefix: Prefix for nested parameters
            results: List to append results to
        """
        param_name = f"{prefix}.{element.tag}" if prefix else element.tag

        # Check if element has attributes
        for attr_name, attr_value in element.attrib.items():
            attr_param = f"{param_name}@{attr_name}"
            result = InjectionPointResult(
                parameter_name=attr_param,
                parameter_type=self.PARAM_TYPE_XML,
                original_value=attr_value,
                test_value=attr_value,
                location=self.base_url,
                value_type="string",
            )
            result.confidence = self._calculate_confidence(
                attr_param, self.PARAM_TYPE_XML
            )
            result.risk_level = self._get_risk_level(result.confidence)
            results.append(result)

        # Check if element has text
        if element.text and element.text.strip():
            result = InjectionPointResult(
                parameter_name=param_name,
                parameter_type=self.PARAM_TYPE_XML,
                original_value=element.text.strip(),
                test_value=element.text.strip(),
                location=self.base_url,
                value_type="string",
            )
            result.confidence = self._calculate_confidence(
                param_name, self.PARAM_TYPE_XML
            )
            result.risk_level = self._get_risk_level(result.confidence)
            results.append(result)

        # Recursive for children
        for child in element:
            self._discover_xml_recursive(child, param_name, results)

    def discover_cookie_parameters(
        self, cookies: dict[str, str]
    ) -> list[InjectionPointResult]:
        """
        Discover parameters from cookies.

        Args:
            cookies: Cookie dictionary

        Returns:
            List[InjectionPointResult]: Discovered parameters
        """
        self.logger.info("[InjectionDiscovery] Discovering cookie parameters...")

        results = []

        try:
            for name, value in cookies.items():
                result = InjectionPointResult(
                    parameter_name=name,
                    parameter_type=self.PARAM_TYPE_COOKIE,
                    original_value=value,
                    test_value=value,
                    location=self.base_url,
                    value_type=self._get_parameter_type(value),
                )
                result.confidence = self._calculate_confidence(
                    name, self.PARAM_TYPE_COOKIE
                )
                result.risk_level = self._get_risk_level(result.confidence)
                results.append(result)
                self.logger.debug(f"[InjectionDiscovery] Found cookie: {name}={value}")

        except Exception as e:
            self.logger.warning(f"[InjectionDiscovery] Failed to parse cookies: {e!s}")

        self.logger.info(f"[InjectionDiscovery] Found {len(results)} cookie parameters")
        return results

    def discover_header_parameters(
        self, headers: dict[str, str]
    ) -> list[InjectionPointResult]:
        """
        Discover parameters from HTTP headers.

        Args:
            headers: Header dictionary

        Returns:
            List[InjectionPointResult]: Discovered parameters
        """
        self.logger.info("[InjectionDiscovery] Discovering header parameters...")

        results = []

        # Headers that are more likely to be used in injections
        suspicious_headers = [
            "User-Agent",
            "Referer",
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Originating-IP",
            "X-Remote-IP",
            "X-Client-IP",
            "X-Host",
            "Host",
            "Origin",
            "Cookie",
            "Authorization",
            "X-Auth-Token",
            "API-Key",
            "X-API-Key",
            "X-Api-Key",
            "Accept-Language",
            "Accept-Encoding",
            "Accept-Charset",
        ]

        try:
            for name, value in headers.items():
                if name in suspicious_headers or "x-" in name.lower():
                    result = InjectionPointResult(
                        parameter_name=name,
                        parameter_type=self.PARAM_TYPE_HEADER,
                        original_value=value,
                        test_value=value,
                        location=self.base_url,
                        value_type=self._get_parameter_type(value),
                    )
                    # Headers get higher confidence if suspicious
                    confidence = self._calculate_confidence(
                        name, self.PARAM_TYPE_HEADER
                    )
                    if name in suspicious_headers:
                        confidence += 10
                    result.confidence = min(confidence, 100)
                    result.risk_level = self._get_risk_level(result.confidence)
                    results.append(result)
                    self.logger.debug(
                        f"[InjectionDiscovery] Found header: {name}={value}"
                    )

        except Exception as e:
            self.logger.warning(f"[InjectionDiscovery] Failed to parse headers: {e!s}")

        self.logger.info(f"[InjectionDiscovery] Found {len(results)} header parameters")
        return results

    def test_parameter(
        self, injection_point: InjectionPointResult, test_value: str
    ) -> InjectionPointResult:
        """
        Test a parameter with a test value.

        Args:
            injection_point: Parameter to test
            test_value: Test value to use

        Returns:
            InjectionPointResult: Updated result
        """
        result = injection_point
        result.test_value = test_value

        # Simple heuristic - if it's a suspicious parameter, mark as injectable
        if self._is_suspicious(result.parameter_name):
            result.is_injectable = True
            result.confidence = min(result.confidence + 20, 100)
            result.add_evidence(f"Suspicious parameter name: {result.parameter_name}")
            result.reason = "Parameter name suggests injection potential"

        # Check for common injection patterns in the value
        injection_patterns = [
            r"select.*from",
            r"union.*select",
            r"or\s+1=1",
            r"and\s+1=1",
            r"--",
            r"#",
            r"/[*]",
        ]

        for pattern in injection_patterns:
            if re.search(pattern, test_value, re.IGNORECASE):
                result.is_injectable = True
                result.confidence = min(result.confidence + 15, 100)
                result.add_evidence(f"Contains injection pattern: {pattern}")
                result.reason = "Test value contains injection pattern"
                break

        return result

    # ============================================================
    # Main Discovery Method
    # ============================================================

    def discover_all(
        self,
        url: str,
        data: str | dict | None = None,
        json_data: str | dict | None = None,
        xml_data: str | None = None,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        test_parameters: bool = True,
    ) -> InjectionDiscoveryResult:
        """
        Discover all injection points from a request.

        Args:
            url: Request URL
            data: POST form data
            json_data: JSON data
            xml_data: XML data
            cookies: Cookie dictionary
            headers: Header dictionary
            test_parameters: Whether to test parameters

        Returns:
            InjectionDiscoveryResult: Complete discovery result
        """
        self.logger.info(
            "[InjectionDiscovery] =================================================="
        )
        self.logger.info("[InjectionDiscovery] PHASE 8: Injection Point Discovery")
        self.logger.info(
            "[InjectionDiscovery] =================================================="
        )

        result = InjectionDiscoveryResult()
        total_start = time.time()

        try:
            # Step 1: Discover GET parameters
            self.logger.info(
                "[InjectionDiscovery] Step 1: Discovering GET parameters..."
            )
            get_params = self.discover_get_parameters(url)
            for param in get_params:
                if test_parameters:
                    param = self.test_parameter(param, f"{param.original_value}'")
                result.add_parameter(param)

            # Step 2: Discover POST parameters
            if data:
                self.logger.info(
                    "[InjectionDiscovery] Step 2: Discovering POST parameters..."
                )
                post_params = self.discover_post_parameters(data)
                for param in post_params:
                    if test_parameters:
                        param = self.test_parameter(param, f"{param.original_value}'")
                    result.add_parameter(param)

            # Step 3: Discover JSON parameters
            if json_data:
                self.logger.info(
                    "[InjectionDiscovery] Step 3: Discovering JSON parameters..."
                )
                json_params = self.discover_json_parameters(json_data)
                for param in json_params:
                    if test_parameters:
                        param = self.test_parameter(param, f"{param.original_value}'")
                    result.add_parameter(param)

            # Step 4: Discover XML parameters
            if xml_data:
                self.logger.info(
                    "[InjectionDiscovery] Step 4: Discovering XML parameters..."
                )
                xml_params = self.discover_xml_parameters(xml_data)
                for param in xml_params:
                    if test_parameters:
                        param = self.test_parameter(param, f"{param.original_value}'")
                    result.add_parameter(param)

            # Step 5: Discover Cookie parameters
            if cookies:
                self.logger.info(
                    "[InjectionDiscovery] Step 5: Discovering Cookie parameters..."
                )
                cookie_params = self.discover_cookie_parameters(cookies)
                for param in cookie_params:
                    if test_parameters:
                        param = self.test_parameter(param, f"{param.original_value}'")
                    result.add_parameter(param)

            # Step 6: Discover Header parameters
            if headers:
                self.logger.info(
                    "[InjectionDiscovery] Step 6: Discovering Header parameters..."
                )
                header_params = self.discover_header_parameters(headers)
                for param in header_params:
                    if test_parameters:
                        param = self.test_parameter(param, f"{param.original_value}'")
                    result.add_parameter(param)

            result.success = True

        except Exception as e:
            error_msg = f"Injection point discovery failed: {e!s}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        result.execution_time = time.time() - total_start

        self.logger.info(
            "[InjectionDiscovery] =================================================="
        )
        self.logger.info("[InjectionDiscovery] INJECTION POINT DISCOVERY COMPLETE")
        self.logger.info(f"[InjectionDiscovery] {result.get_summary()}")
        self.logger.info(f"[InjectionDiscovery] Time: {result.execution_time:.2f}s")
        self.logger.info(
            "[InjectionDiscovery] =================================================="
        )

        self.discovery_result = result
        return result

    # ============================================================
    # Convenience Methods
    # ============================================================

    def get_best_parameter(self) -> InjectionPointResult | None:
        """Get the best injection point."""
        if self.discovery_result:
            return self.discovery_result.get_best_parameter()
        return None

    def get_injectable_parameters(self) -> list[InjectionPointResult]:
        """Get all injectable parameters."""
        if self.discovery_result:
            return self.discovery_result.get_injectable_parameters()
        return []

    def count_parameters(self) -> int:
        """Get total number of parameters."""
        if self.discovery_result:
            return self.discovery_result.count_parameters()
        return 0

    def count_injectable(self) -> int:
        """Get number of injectable parameters."""
        if self.discovery_result:
            return self.discovery_result.count_injectable()
        return 0
