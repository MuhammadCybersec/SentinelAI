"""
SentinelAI Payload Injector - Reusable request-transformation utility.

Provides controlled manipulation of URL components, query parameters,
headers, cookies, request bodies, and form data while preserving
the original request structure.

Design Principles:
- Single Responsibility: Only transforms requests, does not send them
- Open/Closed: Extensible for new injection points
- Dependency Inversion: No direct dependencies on HTTP clients
- Interface Segregation: Focused, clear methods

Version: 1.1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# ============================================================
# Data Models
# ============================================================


@dataclass(slots=True)
class InjectionPoint:
    """
    Represents a location where a payload can be injected.

    Attributes:
        location: Where to inject (query, body, header, cookie, path, json, xml, form)
        parameter: Parameter name (for query, body, header, cookie, form)
        position: Position within the parameter value (prefix, suffix, replace, append)
        original_value: Original value before injection
        payload: The payload to inject
    """

    location: str
    parameter: str
    position: str
    original_value: str = ""
    payload: str = ""


@dataclass(slots=True)
class TransformedRequest:
    """
    Immutable representation of a transformed request.

    Attributes:
        url: Transformed URL with injected payloads
        method: HTTP method (GET, POST, etc.)
        headers: Transformed headers
        cookies: Transformed cookies
        body: Transformed request body
        json_data: Transformed JSON payload (if applicable)
        xml_data: Transformed XML payload (if applicable)
        form_data: Transformed form data (if applicable)
        original_url: Original URL before transformation
        injection_points: List of injection points applied
    """

    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: str = ""
    json_data: dict[str, Any] | None = None
    xml_data: str | None = None
    form_data: dict[str, str] | None = None
    original_url: str = ""
    injection_points: list[InjectionPoint] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.url or not isinstance(self.url, str):
            raise ValueError(f"Invalid URL: {self.url}")


# ============================================================
# Payload Injector
# ============================================================


class PayloadInjector:
    """
    Reusable request-transformation utility for security scanners.

    Features:
        - URL parsing and safe manipulation
        - Query parameter injection (append, replace, prefix, suffix)
        - Form field injection (append, replace, prefix, suffix)
        - Path segment injection
        - Header injection (add, replace, delete)
        - Cookie injection (add, replace, delete)
        - JSON payload injection
        - XML payload injection
        - Form data injection
        - Proper URL encoding/decoding
        - Duplicate parameter handling
        - Fragment preservation
    """

    def __init__(self, url: str) -> None:
        """
        Initialize the PayloadInjector with a target URL.

        Args:
            url: Target URL to transform

        Raises:
            ValueError: If URL is invalid
        """
        if not url or not isinstance(url, str):
            raise ValueError(f"Invalid URL: {url}")
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL: {url}")

        self.original_url: str = url
        self._parsed_url = urlparse(url)
        self._query_params: dict[str, list[str]] = self._parse_query_params()

    # ============================================================
    # Query Parameter Injection
    # ============================================================

    def inject_query_parameter(
        self, parameter: str, payload: str, position: str = "replace"
    ) -> TransformedRequest:
        """
        Inject a payload into a query parameter.

        Args:
            parameter: Parameter name to inject into
            payload: Payload to inject
            position: Where to inject - "replace", "prefix", "suffix", "append"

        Returns:
            TransformedRequest with injected payload
        """
        if position not in ["replace", "prefix", "suffix", "append"]:
            raise ValueError(f"Invalid position: {position}")

        original_value = self._get_parameter_value(parameter)
        new_value = self._transform_value(original_value, payload, position)

        transformed_params = self._query_params.copy()
        transformed_params[parameter] = [new_value]

        self._query_params = transformed_params

        new_url = self._build_url(self._query_params)

        injection_point = InjectionPoint(
            location="query",
            parameter=parameter,
            position=position,
            original_value=original_value,
            payload=payload,
        )

        return TransformedRequest(
            url=new_url,
            method="GET",
            original_url=self.original_url,
            injection_points=[injection_point],
        )

    # ============================================================
    # Form Field Injection
    # ============================================================

    def inject_form_field(
        self,
        form_data: dict[str, str],
        field_name: str,
        payload: str,
        position: str = "replace",
    ) -> dict[str, str]:
        """
        Inject payload into a form field.

        Args:
            form_data: Original form data dictionary
            field_name: Field name to inject into
            payload: Payload to inject
            position: Where to inject - "replace", "prefix", "suffix", "append"

        Returns:
            Updated form data dictionary
        """
        if position not in ["replace", "prefix", "suffix", "append"]:
            raise ValueError(f"Invalid position: {position}")

        original_value = form_data.get(field_name, "")
        new_value = self._transform_value(original_value, payload, position)

        form_data[field_name] = new_value
        return form_data

    # ============================================================
    # Form Data Injection (Full Form)
    # ============================================================

    def inject_form_data(
        self, field_name: str, payload: str, position: str = "replace"
    ) -> TransformedRequest:
        """
        Inject a payload into form data (URL-encoded body).

        Args:
            field_name: Form field name to inject into
            payload: Payload to inject
            position: Where to inject - "replace", "prefix", "suffix", "append"

        Returns:
            TransformedRequest with injected payload
        """
        if position not in ["replace", "prefix", "suffix", "append"]:
            raise ValueError(f"Invalid position: {position}")

        original_value = ""
        new_value = self._transform_value(original_value, payload, position)
        form_data = {field_name: new_value}

        injection_point = InjectionPoint(
            location="body",
            parameter=field_name,
            position=position,
            original_value=original_value,
            payload=payload,
        )
        body = urlencode(form_data)

        return TransformedRequest(
            url=self.original_url,
            method="POST",
            body=body,
            form_data=form_data,
            original_url=self.original_url,
            injection_points=[injection_point],
        )

    # ============================================================
    # Path Segment Injection
    # ============================================================

    def inject_path_segment(
        self, segment_index: int, payload: str, position: str = "replace"
    ) -> TransformedRequest:
        """
        Inject a payload into a path segment.

        Args:
            segment_index: Index of the path segment to modify
            payload: Payload to inject
            position: Where to inject - "replace", "prefix", "suffix", "append"

        Returns:
            TransformedRequest with injected payload
        """
        if position not in ["replace", "prefix", "suffix", "append"]:
            raise ValueError(f"Invalid position: {position}")

        segments = self._parsed_url.path.strip("/").split("/")
        if segment_index >= len(segments):
            raise IndexError(f"Segment index {segment_index} out of range.")

        original_value = segments[segment_index]
        new_value = self._transform_value(original_value, payload, position)
        segments[segment_index] = new_value

        new_path = "/" + "/".join(segments)
        new_url = self._parsed_url._replace(path=new_path).geturl()

        injection_point = InjectionPoint(
            location="path",
            parameter=str(segment_index),
            position=position,
            original_value=original_value,
            payload=payload,
        )

        return TransformedRequest(
            url=new_url,
            method="GET",
            original_url=self.original_url,
            injection_points=[injection_point],
        )

    # ============================================================
    # Header Injection
    # ============================================================

    def inject_header(
        self, header_name: str, payload: str, position: str = "replace"
    ) -> TransformedRequest:
        """
        Inject a payload into a header.

        Args:
            header_name: Header name to inject into
            payload: Payload to inject
            position: Where to inject - "replace", "prefix", "suffix", "append"

        Returns:
            TransformedRequest with injected payload
        """
        if position not in ["replace", "prefix", "suffix", "append"]:
            raise ValueError(f"Invalid position: {position}")

        injection_point = InjectionPoint(
            location="header",
            parameter=header_name,
            position=position,
            original_value="",
            payload=payload,
        )

        return TransformedRequest(
            url=self.original_url,
            method="GET",
            headers={header_name: payload},
            original_url=self.original_url,
            injection_points=[injection_point],
        )

    # ============================================================
    # Cookie Injection
    # ============================================================

    def inject_cookie(
        self, cookie_name: str, payload: str, position: str = "replace"
    ) -> TransformedRequest:
        """
        Inject a payload into a cookie.

        Args:
            cookie_name: Cookie name to inject into
            payload: Payload to inject
            position: Where to inject - "replace", "prefix", "suffix", "append"

        Returns:
            TransformedRequest with injected payload
        """
        if position not in ["replace", "prefix", "suffix", "append"]:
            raise ValueError(f"Invalid position: {position}")

        injection_point = InjectionPoint(
            location="cookie",
            parameter=cookie_name,
            position=position,
            original_value="",
            payload=payload,
        )

        return TransformedRequest(
            url=self.original_url,
            method="GET",
            cookies={cookie_name: payload},
            original_url=self.original_url,
            injection_points=[injection_point],
        )

    # ============================================================
    # JSON Payload Injection
    # ============================================================

    def inject_json_payload(
        self, path: list[str], payload: Any, position: str = "replace"
    ) -> TransformedRequest:
        """
        Inject a payload into a JSON document.

        Args:
            path: List of keys to navigate to the target field
            payload: Payload to inject
            position: Where to inject - "replace", "prefix", "suffix", "append"

        Returns:
            TransformedRequest with injected payload
        """
        if position not in ["replace", "prefix", "suffix", "append"]:
            raise ValueError(f"Invalid position: {position}")

        json_data = self._inject_json_path({}, path, payload)

        injection_point = InjectionPoint(
            location="json",
            parameter=".".join(path),
            position=position,
            original_value="",
            payload=str(payload),
        )

        return TransformedRequest(
            url=self.original_url,
            method="POST",
            json_data=json_data,
            original_url=self.original_url,
            injection_points=[injection_point],
        )

    # ============================================================
    # XML Payload Injection
    # ============================================================

    def inject_xml_payload(
        self, xpath: str, payload: str, position: str = "replace"
    ) -> TransformedRequest:
        """
        Inject a payload into an XML document.

        Args:
            xpath: XPath to the target element
            payload: Payload to inject
            position: Where to inject - "replace", "prefix", "suffix", "append"

        Returns:
            TransformedRequest with injected payload
        """
        if position not in ["replace", "prefix", "suffix", "append"]:
            raise ValueError(f"Invalid position: {position}")

        escaped_payload = self._escape_xml(payload)
        xml_data = f"<root><{xpath}>{escaped_payload}</{xpath}></root>"

        injection_point = InjectionPoint(
            location="xml",
            parameter=xpath,
            position=position,
            original_value="",
            payload=payload,
        )

        return TransformedRequest(
            url=self.original_url,
            method="POST",
            xml_data=xml_data,
            original_url=self.original_url,
            injection_points=[injection_point],
        )

    # ============================================================
    # Helper Methods
    # ============================================================

    def get_all_parameters(self) -> list[str]:
        """Get all query parameter names."""
        return list(self._query_params.keys())

    def get_parameter_value(self, parameter: str) -> str:
        """Get the value of a query parameter."""
        return self._get_parameter_value(parameter)

    def has_parameter(self, parameter: str) -> bool:
        """Check if a query parameter exists."""
        return parameter in self._query_params

    def get_original_url(self) -> str:
        """Get the original URL."""
        return self.original_url

    def reset(self) -> None:
        """Reset the injector to its original state."""
        self._query_params = self._parse_query_params()
        self._parsed_url = urlparse(self.original_url)

    # ============================================================
    # Private Methods
    # ============================================================

    def _parse_query_params(self) -> dict[str, list[str]]:
        """Parse query parameters from the URL."""
        query = self._parsed_url.query
        return parse_qs(query, keep_blank_values=True) if query else {}

    def _build_url(self, params: dict[str, list[str]]) -> str:
        """Build a URL from parsed components."""
        from urllib.parse import quote

        query = urlencode(params, doseq=True, quote_via=quote)
        return urlunparse(
            (
                self._parsed_url.scheme,
                self._parsed_url.netloc,
                self._parsed_url.path,
                self._parsed_url.params,
                query,
                self._parsed_url.fragment,
            )
        )

    def _get_parameter_value(self, parameter: str) -> str:
        """Get the value of a query parameter."""
        values = self._query_params.get(parameter, [])
        return values[0] if values else ""

    def _transform_value(self, original: str, payload: str, position: str) -> str:
        """Transform a value based on the injection position."""
        if position == "replace":
            return payload
        elif position == "prefix":
            return f"{payload}{original}"
        elif position == "suffix" or position == "append":
            return f"{original}{payload}"
        return original

    def _inject_json_path(
        self, data: dict[str, Any], path: list[str], value: Any
    ) -> dict[str, Any]:
        """Recursively inject a value into a JSON path."""
        if not path:
            return data
        key = path[0]
        if len(path) == 1:
            data[key] = value
        else:
            data[key] = self._inject_json_path({}, path[1:], value)
        return data

    def _escape_xml(self, text: str) -> str:
        """Escape XML special characters."""
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")
        text = text.replace('"', "&quot;")
        text = text.replace("'", "&apos;")
        return text

    def __repr__(self) -> str:
        return f"PayloadInjector(url='{self.original_url}')"


# ============================================================
# Factory Function
# ============================================================


def create_payload_injector(url: str) -> PayloadInjector:
    """
    Factory function to create a PayloadInjector instance.

    Args:
        url: Target URL

    Returns:
        PayloadInjector instance
    """
    return PayloadInjector(url)
