# app/modules/scanner/waf_detector.py
"""
Web Application Firewall (WAF) Detection & Fingerprinting Engine for SentinelAI.
Phase 14: WAF Detection and Fingerprinting
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple, Set
import requests

from .union_sqli import UnionSQLi
from .html_parser import HTMLParser
from .regex_utils import RegexUtils

# ============================================================
# Data Classes
# ============================================================


@dataclass
class WAFDetectionResult:
    """
    WAF detection and fingerprinting result.
    """

    success: bool = False
    waf_detected: bool = False
    waf_name: Optional[str] = None
    vendor: Optional[str] = None
    version: Optional[str] = None
    confidence: int = 0
    fingerprints: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    response_codes: List[int] = field(default_factory=list)
    blocked_payloads: List[str] = field(default_factory=list)
    bypass_candidates: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    risk_level: str = "LOW"
    bypass_recommendations: List[str] = field(default_factory=list)
    tamper_suggestions: List[str] = field(default_factory=list)

    def add_error(self, error: str):
        """Add an error to the result."""
        if error and error not in self.errors:
            self.errors.append(error)

    def add_evidence(self, evidence: str):
        """Add evidence to the result."""
        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)

    def add_fingerprint(self, fingerprint: str):
        """Add a fingerprint to the result."""
        if fingerprint and fingerprint not in self.fingerprints:
            self.fingerprints.append(fingerprint)

    def add_bypass_candidate(self, candidate: str):
        """Add a bypass candidate to the result."""
        if candidate and candidate not in self.bypass_candidates:
            self.bypass_candidates.append(candidate)

    def add_bypass_recommendation(self, recommendation: str):
        """Add a bypass recommendation to the result."""
        if recommendation and recommendation not in self.bypass_recommendations:
            self.bypass_recommendations.append(recommendation)

    def add_tamper_suggestion(self, suggestion: str):
        """Add a tamper suggestion to the result."""
        if suggestion and suggestion not in self.tamper_suggestions:
            self.tamper_suggestions.append(suggestion)

    def get_summary(self) -> str:
        """Get a summary of the detection result."""
        if not self.success:
            return "WAF detection failed"

        if not self.waf_detected:
            return "No WAF detected"

        parts = []
        if self.waf_name:
            parts.append(f"WAF: {self.waf_name}")
        if self.vendor:
            parts.append(f"Vendor: {self.vendor}")
        if self.confidence > 0:
            parts.append(f"Confidence: {self.confidence}%")
        if self.fingerprints:
            parts.append(f"Fingerprints: {len(self.fingerprints)}")
        if self.bypass_recommendations:
            parts.append(f"Bypasses: {len(self.bypass_recommendations)}")
        if self.risk_level:
            parts.append(f"Risk: {self.risk_level}")

        return f"WAF: {', '.join(parts)}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "success": self.success,
            "waf_detected": self.waf_detected,
            "waf_name": self.waf_name,
            "vendor": self.vendor,
            "version": self.version,
            "confidence": self.confidence,
            "fingerprints": self.fingerprints,
            "headers": self.headers,
            "cookies": self.cookies,
            "response_codes": self.response_codes,
            "blocked_payloads": self.blocked_payloads,
            "bypass_candidates": self.bypass_candidates,
            "evidence": self.evidence,
            "errors": self.errors,
            "execution_time": self.execution_time,
            "risk_level": self.risk_level,
            "bypass_recommendations": self.bypass_recommendations,
            "tamper_suggestions": self.tamper_suggestions,
            "summary": self.get_summary(),
        }


# ============================================================
# Main WAF Detector Class
# ============================================================


class WAFDetector:
    """
    Web Application Firewall (WAF) Detection & Fingerprinting Engine.
    Phase 14: Detects and fingerprints WAFs.
    """

    # ============================================================
    # Constants
    # ============================================================

    # WAF fingerprints
    WAF_FINGERPRINTS = {
        "Cloudflare": {
            "headers": ["CF-Ray", "CF-Cache-Status", "CF-Connecting-IP", "CF-Worker"],
            "server": ["cloudflare"],
            "cookies": ["__cfduid", "__cf_bm"],
            "body": ["Cloudflare", "cf-request-id"],
            "block_pages": ["Performance & Security by Cloudflare"],
        },
        "AWS WAF": {
            "headers": ["X-Amzn-RequestId", "X-Amzn-Trace-Id"],
            "server": ["aws", "Amazon"],
            "cookies": ["AWSALB", "AWSALBCORS"],
            "body": ["AWS WAF", "Request blocked by AWS WAF"],
            "block_pages": ["403 Forbidden", "Request blocked"],
        },
        "Imperva SecureSphere": {
            "headers": ["X-Imperva-Agent", "X-Imperva-Bot"],
            "server": ["Imperva"],
            "cookies": ["imperva", "visid_incap"],
            "body": ["Incapsula", "Imperva"],
            "block_pages": ["Incapsula incident ID"],
        },
        "F5 BIG-IP ASM": {
            "headers": ["X-F5-ASM", "X-F5-ASM-Client"],
            "server": ["BigIP"],
            "cookies": ["BIGipServer"],
            "body": ["ASM", "F5"],
            "block_pages": ["Request Rejected", "F5 ASM"],
        },
        "FortiWeb": {
            "headers": ["X-FW-Host", "X-FW-Server"],
            "server": ["FortiWeb"],
            "cookies": ["FORTIWEB"],
            "body": ["FortiWeb", "Fortinet"],
            "block_pages": ["FortiWeb", "Blocked by FortiWeb"],
        },
        "Barracuda": {
            "headers": ["X-Barracuda", "X-Barracuda-Instance"],
            "server": ["Barracuda"],
            "cookies": ["barracuda"],
            "body": ["Barracuda", "Barracuda Web Application Firewall"],
            "block_pages": ["Barracuda WAF", "Blocked by Barracuda"],
        },
        "Sucuri": {
            "headers": ["X-Sucuri", "X-Sucuri-Out", "X-Sucuri-Cache"],
            "server": ["Sucuri"],
            "cookies": ["sucuri"],
            "body": ["Sucuri", "Sucuri CloudProxy"],
            "block_pages": ["Sucuri WebSite Firewall", "CloudProxy"],
        },
        "ModSecurity": {
            "headers": ["X-ModSecurity"],
            "server": ["ModSecurity"],
            "cookies": [],
            "body": ["ModSecurity", "ModSecurity: Access denied"],
            "block_pages": ["Access denied with code 403", "ModSecurity"],
        },
        "Citrix ADC": {
            "headers": ["X-Citrix", "X-NS-Client"],
            "server": ["Citrix", "Netscaler"],
            "cookies": ["NSC_", "NSC_AA"],
            "body": ["Citrix", "Netscaler"],
            "block_pages": ["Citrix ADC", "Netscaler"],
        },
        "DenyALL": {
            "headers": ["X-DenyAll", "X-DAS"],
            "server": ["DenyALL"],
            "cookies": ["DAS_"],
            "body": ["DenyALL", "DAS"],
            "block_pages": ["DenyAll", "Blocked by DenyALL"],
        },
        "Radware": {
            "headers": ["X-Radware", "X-RW-Client"],
            "server": ["Radware"],
            "cookies": ["RW_"],
            "body": ["Radware", "AppWall"],
            "block_pages": ["Radware", "AppWall"],
        },
        "Azure Front Door": {
            "headers": ["X-Azure-Ref", "X-Azure-RequestId"],
            "server": ["Azure"],
            "cookies": ["azure"],
            "body": ["Azure Front Door", "Microsoft Azure"],
            "block_pages": ["Azure Front Door", "Request blocked"],
        },
        "Fastly": {
            "headers": ["X-Served-By", "X-Cache", "X-Cache-Hits", "Fastly"],
            "server": ["Fastly"],
            "cookies": ["fastly"],
            "body": ["Fastly", "Varnish"],
            "block_pages": ["Fastly", "Varnish"],
        },
        "StackPath": {
            "headers": ["X-StackPath", "X-SP-Request-Id"],
            "server": ["StackPath"],
            "cookies": ["sp"],
            "body": ["StackPath", "StackPath CDN"],
            "block_pages": ["StackPath", "Request blocked"],
        },
        "NAXSI": {
            "headers": ["X-NAXSI"],
            "server": ["NAXSI"],
            "cookies": [],
            "body": ["NAXSI", "Naxsi"],
            "block_pages": ["NAXSI", "Blocked by NAXSI"],
        },
        "Wordfence": {
            "headers": ["X-Wordfence", "X-WF-Request-Id"],
            "server": [],
            "cookies": ["wf_"],
            "body": ["Wordfence", "WF"],
            "block_pages": ["Wordfence", "Blocked by Wordfence"],
        },
        "Akamai": {
            "headers": ["X-Akamai", "X-Akamai-Transformed"],
            "server": ["Akamai"],
            "cookies": ["akamai"],
            "body": ["Akamai", "Akamai Ghost"],
            "block_pages": ["Akamai", "Request blocked by Akamai"],
        },
        "Unknown WAF": {
            "headers": [],
            "server": [],
            "cookies": [],
            "body": ["Web Application Firewall", "Access Denied", "Blocked"],
            "block_pages": ["403", "Forbidden", "Access Denied", "Blocked by firewall"],
        },
    }

    # WAF indicators
    WAF_INDICATORS = {
        "blocked_status_codes": [403, 406, 429, 503],
        "security_headers": [
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Permitted-Cross-Domain-Policies",
            "X-Download-Options",
            "Referrer-Policy",
            "Feature-Policy",
        ],
        "blocked_keywords": [
            "blocked",
            "forbidden",
            "denied",
            "firewall",
            "waf",
            "security",
            "breach",
            "attack",
            "suspicious",
            "threat",
            "intrusion",
            "access denied",
            "not allowed",
            "unauthorized",
        ],
    }

    # Bypass recommendations by WAF
    BYPASS_RECOMMENDATIONS = {
        "Cloudflare": [
            "Use IP rotation with different ASNs",
            "Use cloudflare-unsupported headers",
            "Use non-standard user-agents",
            "Use traffic through Tor (partial bypass)",
        ],
        "AWS WAF": [
            "Use API Gateway with different IP ranges",
            "Use HTTPS with custom User-Agent",
            "Use slow HTTP request pacing",
            "Use CloudFront edge locations bypass",
        ],
        "Imperva SecureSphere": [
            "Use incapsula-removal headers",
            "Use different ASN ranges",
            "Use JavaScript-enabled browsers",
            "Use proxied IP addresses",
        ],
        "ModSecurity": [
            "Use case variation (SQL keywords)",
            "Use comment injection (/**/)",
            "Use URL encoding variants",
            "Use whitespace variations",
            "Use hex encoding",
        ],
        "FortiWeb": [
            "Use FortiWeb bypass headers",
            "Use different HTTP methods",
            "Use content-type variations",
            "Use path traversal bypass techniques",
        ],
        "Barracuda": [
            "Use Barracuda bypass payloads",
            "Use SSL/TLS variations",
            "Use different encoding methods",
            "Use multipart/form-data bypass",
        ],
        "Sucuri": [
            "Use Sucuri bypass user-agents",
            "Use IP address whitelist discovery",
            "Use proxied requests",
            "Use subdomain bypass if available",
        ],
        "F5 BIG-IP ASM": [
            "Use ASM bypass headers",
            "Use parameter pollution",
            "Use case-insensitive variations",
            "Use URL encoding bypasses",
        ],
        "Akamai": [
            "Use Akamai edge-side include bypass",
            "Use different origin IPs",
            "Use host header variations",
            "Use TLS fingerprint variations",
        ],
        "General": [
            "Use URL encoding (URL encode payloads)",
            "Use comment injection (/**/)",
            "Use whitespace variations",
            "Use case variation",
            "Use hex encoding",
            "Use string concatenation",
            "Use char function (CHR)",
            "Use double encoding",
            "Use null byte injection",
            "Use HTTP parameter pollution",
        ],
    }

    # ============================================================
    # Initialization
    # ============================================================

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize WAF Detector.

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
        self.baseline_response = None
        self.waf_result = None

        self.logger.info("[WAFDetector] Module initialized for WAF detection")
        self.logger.info(f"[WAFDetector] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("WAFDetector")
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

    def _get_baseline(self) -> Optional[requests.Response]:
        """Get baseline response for comparison."""
        if self.baseline_response is None:
            self.logger.info("[WAFDetector] Fetching baseline response...")
            try:
                self.baseline_response = self.session.get(self.base_url, timeout=10)
                self.logger.info(
                    f"[WAFDetector] Baseline status: {self.baseline_response.status_code}"
                )
            except Exception as e:
                self.logger.warning(f"[WAFDetector] Failed to get baseline: {str(e)}")

        return self.baseline_response

    def _detect_by_headers(self, response: requests.Response) -> List[str]:
        """
        Detect WAF by analyzing response headers.

        Args:
            response: HTTP response

        Returns:
            List[str]: Detected WAF names
        """
        detected = []
        headers = {k.lower(): v for k, v in response.headers.items()}

        for waf_name, fingerprints in self.WAF_FINGERPRINTS.items():
            match_score = 0

            # Check header fingerprints
            for header in fingerprints.get("headers", []):
                if header.lower() in headers:
                    match_score += 1

            # Check server header
            server = headers.get("server", "")
            for server_pattern in fingerprints.get("server", []):
                if server_pattern.lower() in server.lower():
                    match_score += 2

            # Check cookie fingerprints
            set_cookie = headers.get("set-cookie", "")
            for cookie in fingerprints.get("cookies", []):
                if cookie.lower() in set_cookie.lower():
                    match_score += 1

            if match_score >= 2:
                detected.append(waf_name)
                self.logger.debug(
                    f"[WAFDetector] Header match for {waf_name}: score {match_score}"
                )

        return detected

    def _detect_by_body(self, response: requests.Response) -> List[str]:
        """
        Detect WAF by analyzing response body.

        Args:
            response: HTTP response

        Returns:
            List[str]: Detected WAF names
        """
        detected = []
        body = response.text.lower()

        for waf_name, fingerprints in self.WAF_FINGERPRINTS.items():
            match_score = 0

            # Check body patterns
            for pattern in fingerprints.get("body", []):
                if pattern.lower() in body:
                    match_score += 2

            # Check block pages
            for block_page in fingerprints.get("block_pages", []):
                if block_page.lower() in body:
                    match_score += 3

            if match_score >= 2:
                detected.append(waf_name)
                self.logger.debug(
                    f"[WAFDetector] Body match for {waf_name}: score {match_score}"
                )

        return detected

    def _detect_by_status(self, response: requests.Response) -> bool:
        """
        Detect WAF by analyzing status code.

        Args:
            response: HTTP response

        Returns:
            bool: True if WAF detected by status code
        """
        status_code = response.status_code
        if status_code in self.WAF_INDICATORS["blocked_status_codes"]:
            self.logger.debug(f"[WAFDetector] WAF indicator status code: {status_code}")
            return True
        return False

    def _detect_by_block_page(self, response: requests.Response) -> bool:
        """
        Detect WAF by analyzing block page.

        Args:
            response: HTTP response

        Returns:
            bool: True if block page detected
        """
        body = response.text.lower()

        # Check for block page keywords
        for keyword in self.WAF_INDICATORS["blocked_keywords"]:
            if keyword in body:
                self.logger.debug(f"[WAFDetector] Block page keyword found: {keyword}")
                return True

        return False

    def _detect_by_payload(
        self, injection_point: str, test_payload: str
    ) -> Dict[str, Any]:
        """
        Detect WAF by testing a payload.

        Args:
            injection_point: Parameter to inject into
            test_payload: Payload to test

        Returns:
            Dict: Detection results
        """
        self.logger.debug(f"[WAFDetector] Testing payload: {test_payload[:50]}...")

        baseline = self._get_baseline()
        result = self.union_sqli.test_payload(injection_point, test_payload, baseline)

        if not result["success"] or result.get("response") is None:
            return {"blocked": False, "response": None}

        response = result["response"]

        # Check if payload was blocked
        is_blocked = response.status_code in self.WAF_INDICATORS[
            "blocked_status_codes"
        ] or self._detect_by_block_page(response)

        return {
            "blocked": is_blocked,
            "response": response,
            "status_code": response.status_code,
            "size": len(response.text),
        }

    def _calculate_confidence(
        self,
        header_matches: int,
        body_matches: int,
        status_matches: int,
        payload_blocked: bool,
    ) -> int:
        """
        Calculate confidence score.

        Args:
            header_matches: Number of header matches
            body_matches: Number of body matches
            status_matches: Number of status code matches
            payload_blocked: Whether payload was blocked

        Returns:
            int: Confidence score (0-100)
        """
        confidence = 0

        # Header matches
        if header_matches >= 3:
            confidence += 40
        elif header_matches >= 2:
            confidence += 30
        elif header_matches >= 1:
            confidence += 15

        # Body matches
        if body_matches >= 3:
            confidence += 35
        elif body_matches >= 2:
            confidence += 25
        elif body_matches >= 1:
            confidence += 10

        # Status matches
        if status_matches >= 2:
            confidence += 20
        elif status_matches >= 1:
            confidence += 10

        # Payload blocked
        if payload_blocked:
            confidence += 20

        return min(confidence, 100)

    # ============================================================
    # Public Methods
    # ============================================================

    def detect(self, injection_point: Optional[str] = None) -> WAFDetectionResult:
        """
        Detect and fingerprint WAF.

        Args:
            injection_point: Parameter to inject into (optional)

        Returns:
            WAFDetectionResult: Detection result
        """
        self.logger.info(
            "[WAFDetector] =================================================="
        )
        self.logger.info("[WAFDetector] PHASE 14: WAF Detection & Fingerprinting")
        self.logger.info(
            "[WAFDetector] =================================================="
        )

        result = WAFDetectionResult()
        total_start = time.time()

        try:
            # Get baseline
            baseline = self._get_baseline()
            if not baseline:
                result.add_error("Failed to get baseline response")
                return result

            # Collect headers
            result.headers = dict(baseline.headers)

            # Collect cookies
            if "Set-Cookie" in baseline.headers:
                result.cookies = baseline.headers.get("Set-Cookie", "").split(";")

            # Collect response codes
            result.response_codes.append(baseline.status_code)

            # Step 1: Detect by headers
            self.logger.info("[WAFDetector] Detecting by headers...")
            header_detected = self._detect_by_headers(baseline)
            for waf in header_detected:
                result.add_evidence(f"Header fingerprint: {waf}")
                result.add_fingerprint(f"Header: {waf}")

            # Step 2: Detect by body
            self.logger.info("[WAFDetector] Detecting by body...")
            body_detected = self._detect_by_body(baseline)
            for waf in body_detected:
                result.add_evidence(f"Body fingerprint: {waf}")
                result.add_fingerprint(f"Body: {waf}")

            # Step 3: Detect by status code
            self.logger.info("[WAFDetector] Detecting by status code...")
            status_detected = self._detect_by_status(baseline)
            if status_detected:
                result.add_evidence(f"Status code indicator: {baseline.status_code}")

            # Step 4: Detect by block page
            self.logger.info("[WAFDetector] Detecting by block page...")
            block_page_detected = self._detect_by_block_page(baseline)
            if block_page_detected:
                result.add_evidence("Block page detected")

            # Step 5: Detect by payload (if injection point provided)
            if injection_point:
                self.logger.info("[WAFDetector] Detecting by test payload...")
                test_payload = "' OR 1=1--"
                payload_result = self._detect_by_payload(injection_point, test_payload)

                if payload_result.get("blocked"):
                    result.add_evidence("Test payload blocked by WAF")
                    result.blocked_payloads.append(test_payload)
                    result.add_bypass_candidate("Use comment injection")
                    result.add_bypass_candidate("Use URL encoding")

            # Combine all detections
            all_detected = set(header_detected + body_detected)

            # Determine best WAF match
            if all_detected:
                # Prefer WAFs with more specific fingerprints
                result.waf_detected = True

                # Find best match
                best_waf = None
                best_score = 0

                for waf_name in all_detected:
                    score = 0
                    if waf_name in header_detected:
                        score += 2
                    if waf_name in body_detected:
                        score += 2
                    if waf_name in self.WAF_FINGERPRINTS:
                        # Check for block pages
                        fingerprints = self.WAF_FINGERPRINTS.get(waf_name, {})
                        for block_page in fingerprints.get("block_pages", []):
                            if block_page.lower() in baseline.text.lower():
                                score += 3

                    if score > best_score:
                        best_score = score
                        best_waf = waf_name

                if best_waf:
                    result.waf_name = best_waf
                    result.vendor = best_waf

                    # Add bypass recommendations - case insensitive lookup
                    for waf_key, bypasses in self.BYPASS_RECOMMENDATIONS.items():
                        if (
                            best_waf.lower() in waf_key.lower()
                            or waf_key.lower() in best_waf.lower()
                        ):
                            for bypass in bypasses:
                                result.add_bypass_recommendation(bypass)

                    # Add general bypasses
                    for bypass in self.BYPASS_RECOMMENDATIONS.get("General", []):
                        result.add_bypass_recommendation(bypass)

            # Calculate confidence
            result.confidence = self._calculate_confidence(
                len(header_detected),
                len(body_detected),
                1 if status_detected else 0,
                bool(result.blocked_payloads),
            )

            # Determine risk level
            if result.confidence >= 80:
                result.risk_level = "HIGH"
            elif result.confidence >= 60:
                result.risk_level = "MEDIUM"
            else:
                result.risk_level = "LOW"

            result.success = True

        except Exception as e:
            error_msg = f"WAF detection failed: {str(e)}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        result.execution_time = time.time() - total_start

        self.logger.info(
            "[WAFDetector] =================================================="
        )
        self.logger.info("[WAFDetector] WAF DETECTION COMPLETE")
        self.logger.info(f"[WAFDetector] {result.get_summary()}")
        self.logger.info(f"[WAFDetector] Time: {result.execution_time:.2f}s")
        self.logger.info(
            "[WAFDetector] =================================================="
        )

        self.waf_result = result
        return result

    def detect_by_headers(self, response: requests.Response) -> List[str]:
        """Detect WAF by headers."""
        return self._detect_by_headers(response)

    def detect_by_body(self, response: requests.Response) -> List[str]:
        """Detect WAF by body."""
        return self._detect_by_body(response)

    def detect_by_status(self, response: requests.Response) -> bool:
        """Detect WAF by status code."""
        return self._detect_by_status(response)

    def detect_by_cookies(self, response: requests.Response) -> List[str]:
        """Detect WAF by cookies."""
        detected = []
        cookies = response.headers.get("Set-Cookie", "")

        for waf_name, fingerprints in self.WAF_FINGERPRINTS.items():
            for cookie in fingerprints.get("cookies", []):
                if cookie.lower() in cookies.lower():
                    detected.append(waf_name)

        return detected

    def detect_by_response(self, response: requests.Response) -> List[str]:
        """Detect WAF by response."""
        detected = []

        # Check headers
        detected.extend(self._detect_by_headers(response))

        # Check body
        detected.extend(self._detect_by_body(response))

        return list(set(detected))

    def detect_by_block_page(self, response: requests.Response) -> bool:
        """Detect block page."""
        return self._detect_by_block_page(response)

    def detect_by_payload(
        self, injection_point: str, test_payload: str
    ) -> Dict[str, Any]:
        """Detect WAF by payload."""
        return self._detect_by_payload(injection_point, test_payload)

    def fingerprint(self, response: requests.Response) -> List[str]:
        """Fingerprint WAF from response."""
        return self.detect_by_response(response)

    def identify_vendor(self, response: requests.Response) -> Optional[str]:
        """Identify WAF vendor."""
        detected = self.detect_by_response(response)
        return detected[0] if detected else None

    def rank_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank detection results."""
        ranked = sorted(results, key=lambda x: x.get("score", 0), reverse=True)
        return ranked

    def calculate_confidence(
        self,
        header_matches: int,
        body_matches: int,
        status_matches: int,
        payload_blocked: bool,
    ) -> int:
        """Calculate confidence score."""
        return self._calculate_confidence(
            header_matches, body_matches, status_matches, payload_blocked
        )

    def collect_evidence(self, response: requests.Response) -> List[str]:
        """Collect evidence from response."""
        evidence = []

        # Status code
        evidence.append(f"Status: {response.status_code}")

        # Headers
        for header, value in response.headers.items():
            evidence.append(f"Header: {header}: {value[:50]}")

        # Body preview
        body_preview = response.text[:200].replace("\n", " ")
        evidence.append(f"Body preview: {body_preview}")

        return evidence

    def is_waf_present(self, injection_point: Optional[str] = None) -> bool:
        """Quick check if WAF is present."""
        result = self.detect(injection_point)
        return result.waf_detected

    def get_waf_name(self, injection_point: Optional[str] = None) -> Optional[str]:
        """Get WAF name."""
        result = self.detect(injection_point)
        return result.waf_name

    def get_bypass_recommendations(
        self, injection_point: Optional[str] = None
    ) -> List[str]:
        """Get bypass recommendations."""
        result = self.detect(injection_point)
        return result.bypass_recommendations
