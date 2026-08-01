"""
SentinelAI Response Analyzer V3
Production Response Intelligence Engine

Used by:
- XSS
- SQLi
- LFI
- RFI
- SSRF
- Command Injection
- CRLF
- Open Redirect
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from typing import Any

# ==========================================================
# Common Regex
# ==========================================================

HTML_TAG_RE = re.compile(r"<[^>]+>")

SCRIPT_RE = re.compile(
    r"<script.*?>.*?</script>",
    re.IGNORECASE | re.DOTALL,
)

HTML_ENTITY_RE = re.compile(r"&[a-zA-Z0-9#]+;")

URL_ENCODE_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# ==========================================================
# Reflection Result
# ==========================================================


@dataclass(slots=True)
class ReflectionResult:
    reflected: bool = False

    count: int = 0

    exact: bool = False

    positions: list[int] = field(
        default_factory=list,
    )


# ==========================================================
# Context Result
# ==========================================================


@dataclass(slots=True)
class ContextResult:
    context: str = "unknown"

    inside_tag: bool = False

    inside_attribute: bool = False

    inside_script: bool = False

    inside_json: bool = False


# ==========================================================
# Risk Result
# ==========================================================


@dataclass(slots=True)
class RiskResult:
    severity: str = "Informational"

    confidence: float = 0.0

    score: int = 0


# ==========================================================
# Final Analysis Result
# ==========================================================


@dataclass(slots=True)
class AnalysisResult:
    url: str = ""

    status_code: int = 0

    response_time: float = 0.0

    reflection: ReflectionResult = field(
        default_factory=ReflectionResult,
    )

    context: ContextResult = field(
        default_factory=ContextResult,
    )
    encoding: str = "unknown"

    risk: RiskResult = field(
        default_factory=RiskResult,
    )

    technologies: list[str] = field(
        default_factory=list,
    )

    waf: str | None = None

    security_headers: dict[str, bool] = field(
        default_factory=dict,
    )

    headers: dict[str, str] = field(
        default_factory=dict,
    )

    evidence: list[str] = field(
        default_factory=list,
    )


# ==========================================================
# Response Analyzer
# ==========================================================


class ResponseAnalyzer:
    """
    SentinelAI Production Response Analyzer.
    """

    VERSION = "3.0.0"

    def __init__(self) -> None:

        self.started_at = 0.0

        self.finished_at = 0.0

        self.total_analyzed = 0
        # ==========================================================

    # Reflection Engine
    # ==========================================================

    def analyze_reflection(
        self,
        response_text: str,
        payload: str,
    ) -> ReflectionResult:
        """
        Analyze payload reflection inside the response.
        """

        result = ReflectionResult()

        if not response_text:
            return result

        if not payload:
            return result

        start = 0

        while True:
            index = response_text.find(
                payload,
                start,
            )

            if index == -1:
                break

            result.reflected = True

            result.exact = True

            result.count += 1

            result.positions.append(index)

            start = index + len(payload)

        # ------------------------------------------
        # Partial Reflection Detection
        # ------------------------------------------

        if not result.reflected:
            payload_tokens = [
                token
                for token in re.split(
                    r"[\s\"'<>()=/]+",
                    payload,
                )
                if len(token) >= 3
            ]

            matched = 0

            for token in payload_tokens:
                if token in response_text:
                    matched += 1

            if matched >= max(2, len(payload_tokens) // 2):
                result.reflected = True

                result.exact = False

                result.count = matched

        return result

    # ==========================================================
    # Helper
    # ==========================================================

    @staticmethod
    def _safe_text(
        response: Any,
    ) -> str:
        """
        Safely extract response text from either
        httpx.Response or Sentinel ResponseData.
        """

        if response is None:
            return ""

        # httpx.Response
        text = getattr(
            response,
            "text",
            None,
        )

        # Sentinel ResponseData
        if text is None:
            text = getattr(
                response,
                "body",
                "",
            )

        if text is None:
            return ""

        return str(
            text,
        )

    # ==========================================================

    # Context Detection Engine
    # ==========================================================

    def analyze_context(
        self,
        response_text: str,
        payload: str,
    ) -> ContextResult:
        """
        Detect where the payload is reflected.
        """

        result = ContextResult()

        if not response_text or not payload:
            return result

        position = response_text.find(payload)

        if position == -1:
            return result

        before = response_text[:position]

        after = response_text[position:]

        # ------------------------------------------------------
        # Script Context
        # ------------------------------------------------------

        last_script_open = before.lower().rfind("<script")
        last_script_close = before.lower().rfind("</script>")

        if last_script_open > last_script_close:
            result.context = "script"

            result.inside_script = True

            return result

        # ------------------------------------------------------
        # HTML Attribute Context
        # ------------------------------------------------------

        tag_open = before.rfind("<")
        tag_close = before.rfind(">")

        if tag_open > tag_close:
            result.inside_tag = True

            quote1 = before.rfind('"')
            quote2 = before.rfind("'")

            if quote1 > tag_open or quote2 > tag_open:
                result.context = "attribute"

                result.inside_attribute = True

                return result

            result.context = "html"

            return result

        # ------------------------------------------------------
        # JSON Context
        # ------------------------------------------------------

        stripped = before.strip()

        if stripped.endswith(":") or stripped.endswith("{"):
            result.context = "json"

            result.inside_json = True

            return result

        # ------------------------------------------------------
        # Default
        # ------------------------------------------------------

        result.context = "text"

        return result
        # ==========================================================

    # HTML Decode Helper
    # ==========================================================

    @staticmethod
    def decode_html(
        value: str,
    ) -> str:
        """
        Decode HTML entities.
        """

        return html.unescape(value)
        # ==========================================================

    # Encoding Detection Engine
    # ==========================================================

    def analyze_encoding(
        self,
        response_text: str,
        payload: str,
    ) -> str:
        """
        Detect payload encoding inside response.
        """

        if not response_text or not payload:
            return "unknown"

        # ----------------------------------------
        # Raw Reflection
        # ----------------------------------------

        if payload in response_text:
            return "raw"

        # ----------------------------------------
        # HTML Encoding
        # ----------------------------------------

        html_encoded = html.escape(
            payload,
            quote=True,
        )

        if html_encoded in response_text:
            return "html"

        # ----------------------------------------
        # Double HTML Encoding
        # ----------------------------------------

        double_encoded = html.escape(
            html_encoded,
            quote=True,
        )

        if double_encoded in response_text:
            return "double_html"

        # ----------------------------------------
        # URL Encoding
        # ----------------------------------------

        from urllib.parse import quote

        url_encoded = quote(
            payload,
            safe="",
        )

        if url_encoded in response_text:
            return "url"

        # ----------------------------------------
        # JavaScript Escaping
        # ----------------------------------------

        js_payload = (
            payload.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'")
        )

        if js_payload in response_text:
            return "javascript"

        return "unknown"
        # ==========================================================

    # Decode Response
    # ==========================================================

    @staticmethod
    def normalize_response(
        response_text: str,
    ) -> str:
        """
        Normalize response before analysis.
        """

        if not response_text:
            return ""

        response_text = html.unescape(
            response_text,
        )

        response_text = response_text.replace(
            "\r",
            "",
        )

        return response_text
        # ==========================================================

    # Technology Detection Engine
    # ==========================================================

    def detect_technologies(
        self,
        response,
    ) -> list[str]:
        """
        Detect web technologies from headers and response body.
        """

        technologies: set[str] = set()

        if response is None:
            return []

        body = self._safe_text(response).lower()

        headers = {}

        if hasattr(response, "headers"):
            try:
                headers = {
                    str(k).lower(): str(v).lower() for k, v in response.headers.items()
                }

            except Exception:
                headers = {}

        server = headers.get(
            "server",
            "",
        )

        powered = headers.get(
            "x-powered-by",
            "",
        )

        generator = headers.get(
            "generator",
            "",
        )

        # --------------------------------------------------
        # Server Technologies
        # --------------------------------------------------

        if "nginx" in server:
            technologies.add("Nginx")

        if "apache" in server:
            technologies.add("Apache")

        if "iis" in server:
            technologies.add("Microsoft IIS")

        if "openresty" in server:
            technologies.add("OpenResty")

        if "cloudflare" in server:
            technologies.add("Cloudflare")

        # --------------------------------------------------
        # Frameworks
        # --------------------------------------------------

        framework_checks = {
            "laravel": "Laravel",
            "symfony": "Symfony",
            "django": "Django",
            "flask": "Flask",
            "express": "Express",
            "next.js": "Next.js",
            "react": "React",
            "vue": "Vue",
            "angular": "Angular",
            "asp.net": "ASP.NET",
            "php": "PHP",
            "wordpress": "WordPress",
        }

        search_space = body + server + powered + generator

        for keyword, name in framework_checks.items():
            if keyword in search_space:
                technologies.add(name)

        # --------------------------------------------------
        # Common Headers
        # --------------------------------------------------

        if "x-aspnet-version" in headers:
            technologies.add("ASP.NET")

        if "x-powered-by" in headers:
            value = headers["x-powered-by"]

            if "php" in value:
                technologies.add("PHP")

            if "express" in value:
                technologies.add("Express")

        return sorted(technologies)
        # ==========================================================

    # WAF Detection Engine
    # ==========================================================

    def detect_waf(
        self,
        response,
    ) -> str | None:
        """
        Detect common Web Application Firewalls.
        """

        if response is None:
            return None

        headers = {}

        try:
            headers = {
                str(k).lower(): str(v).lower() for k, v in response.headers.items()
            }

        except Exception:
            return None

        server = headers.get(
            "server",
            "",
        )

        powered = headers.get(
            "x-powered-by",
            "",
        )

        waf_signature = server + powered + str(headers)

        wafs = {
            "cloudflare": "Cloudflare",
            "cf-ray": "Cloudflare",
            "akamai": "Akamai",
            "imperva": "Imperva",
            "sucuri": "Sucuri",
            "mod_security": "ModSecurity",
            "modsecurity": "ModSecurity",
            "aws": "AWS WAF",
            "azure": "Azure WAF",
            "f5": "F5 BIG-IP",
            "barracuda": "Barracuda",
        }

        for signature, name in wafs.items():
            if signature in waf_signature:
                return name

        return None

    # ==========================================================
    # Security Header Analyzer
    # ==========================================================

    def analyze_security_headers(
        self,
        response,
    ) -> dict[str, bool]:
        """
        Analyze important security headers.
        """

        result = {
            "Content-Security-Policy": False,
            "Strict-Transport-Security": False,
            "X-Frame-Options": False,
            "X-Content-Type-Options": False,
            "Referrer-Policy": False,
            "Permissions-Policy": False,
        }

        if response is None:
            return result

        try:
            headers = {str(k).lower(): str(v) for k, v in response.headers.items()}

        except Exception:
            return result

        mapping = {
            "content-security-policy": "Content-Security-Policy",
            "strict-transport-security": "Strict-Transport-Security",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }

        for header, pretty_name in mapping.items():
            if header in headers:
                result[pretty_name] = True

        return result
        # ==========================================================

    # Confidence Engine
    # ==========================================================

    def calculate_confidence(
        self,
        result: AnalysisResult,
    ) -> float:
        """
        Calculate confidence score (0.0 - 1.0).
        """

        score = 0.0

        # ------------------------------------
        # Reflection
        # ------------------------------------

        if result.reflection.reflected:
            score += 0.40

            if result.reflection.exact:
                score += 0.20

        # ------------------------------------
        # Context
        # ------------------------------------

        context_scores = {
            "script": 0.20,
            "attribute": 0.15,
            "html": 0.10,
            "json": 0.05,
            "text": 0.05,
        }

        score += context_scores.get(
            result.context.context,
            0.0,
        )

        # ------------------------------------
        # Encoding
        # ------------------------------------

        encoding = getattr(
            result,
            "encoding",
            "unknown",
        )

        if encoding == "raw":
            score += 0.15

        elif encoding == "html" or encoding == "javascript":
            score += 0.05

        return round(
            min(score, 1.0),
            2,
        )

    # ==========================================================
    # Risk Engine
    # ==========================================================

    def calculate_risk(
        self,
        result: AnalysisResult,
    ) -> RiskResult:
        """
        Build final risk assessment.
        """

        confidence = self.calculate_confidence(
            result,
        )

        score = int(
            confidence * 100,
        )

        if confidence >= 0.90:
            severity = "Critical"

        elif confidence >= 0.75:
            severity = "High"

        elif confidence >= 0.50:
            severity = "Medium"

        else:
            severity = "Low"

        return RiskResult(
            severity=severity,
            confidence=confidence,
            score=score,
        )

    # ==========================================================

    # Main Analysis Pipeline
    # ==========================================================

    def analyze(
        self,
        response,
        payload: str = "",
    ) -> AnalysisResult:
        """
        Complete response analysis pipeline.
        """

        result = AnalysisResult()

        text = self._safe_text(response)

        text = self.normalize_response(text)

        # ----------------------------------------
        # Reflection
        # ----------------------------------------

        result.reflection = self.analyze_reflection(
            text,
            payload,
        )

        # ----------------------------------------
        # Context
        # ----------------------------------------

        result.context = self.analyze_context(
            text,
            payload,
        )

        # ----------------------------------------
        # Encoding
        # ----------------------------------------

        result.encoding = self.analyze_encoding(
            text,
            payload,
        )

        # ----------------------------------------
        # Technologies
        # ----------------------------------------

        result.technologies = self.detect_technologies(
            response,
        )

        # ----------------------------------------
        # WAF
        # ----------------------------------------

        result.waf = self.detect_waf(
            response,
        )

        # ----------------------------------------
        # Security Headers
        # ----------------------------------------

        result.security_headers = self.analyze_security_headers(
            response,
        )

        # ----------------------------------------
        # Final Risk
        # ----------------------------------------

        result.risk = self.calculate_risk(
            result,
        )

        return result


if __name__ == "__main__":
    from types import SimpleNamespace

    demo = SimpleNamespace(
        text="""
<html>
<body>

<script>

var a="<script>alert(1)</script>";

</script>

</body>
</html>
""",
        headers={
            "Server": "nginx",
            "X-Powered-By": "PHP/8.2",
            "Content-Security-Policy": "default-src 'self'",
        },
    )

    analyzer = ResponseAnalyzer()

    result = analyzer.analyze(
        demo,
        "<script>alert(1)</script>",
    )

    print("=" * 60)
    print("SentinelAI Response Analyzer V3")
    print("=" * 60)
    print()

    print("Reflection :", result.reflection)
    print("Context    :", result.context)
    print("Encoding   :", result.encoding)
    print("Risk       :", result.risk)
    print("WAF        :", result.waf)
    print("Tech       :", result.technologies)
    print("Headers    :", result.security_headers)
