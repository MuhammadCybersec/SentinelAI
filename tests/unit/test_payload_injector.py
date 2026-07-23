"""
Unit tests for PayloadInjector.

These tests cover:
- URL parsing and validation
- Query parameter injection
- Path segment injection
- Header injection
- Cookie injection
- Form data injection
- JSON payload injection
- XML payload injection
- Edge cases (empty values, duplicate params, encoding)
"""

import pytest

from app.modules.scanner.core.payload_injector import (
    PayloadInjector,
    create_payload_injector,
)

# ============================================================
# Fixtures
# ============================================================


@pytest.fixture
def simple_url() -> str:
    """Return a simple URL with no query parameters."""
    return "https://example.com/api/users"


@pytest.fixture
def url_with_params() -> str:
    """Return a URL with query parameters."""
    return "https://example.com/api/users?page=1&limit=10"


@pytest.fixture
def url_with_duplicate_params() -> str:
    """Return a URL with duplicate query parameters."""
    return "https://example.com/api/users?filter=active&filter=verified"


@pytest.fixture
def url_with_encoding() -> str:
    """Return a URL with encoded query parameters."""
    return "https://example.com/api/search?q=hello%20world"


@pytest.fixture
def url_with_fragment() -> str:
    """Return a URL with a fragment identifier."""
    return "https://example.com/api/users?page=1#section"


@pytest.fixture
def injector_simple(simple_url: str) -> PayloadInjector:
    """Return a PayloadInjector for a simple URL."""
    return PayloadInjector(simple_url)


@pytest.fixture
def injector_with_params(url_with_params: str) -> PayloadInjector:
    """Return a PayloadInjector for a URL with parameters."""
    return PayloadInjector(url_with_params)


# ============================================================
# Test URL Validation
# ============================================================


def test_valid_url_creation(simple_url: str) -> None:
    """Test creating a PayloadInjector with a valid URL."""
    injector = PayloadInjector(simple_url)
    assert injector.original_url == simple_url
    assert injector.get_original_url() == simple_url


def test_invalid_url_creation() -> None:
    """Test creating a PayloadInjector with an invalid URL."""
    with pytest.raises(ValueError, match="Invalid URL"):
        PayloadInjector("not-a-url")


def test_empty_url_creation() -> None:
    """Test creating a PayloadInjector with an empty URL."""
    with pytest.raises(ValueError, match="Invalid URL"):
        PayloadInjector("")


def test_factory_function(simple_url: str) -> None:
    """Test the factory function."""
    injector = create_payload_injector(simple_url)
    assert isinstance(injector, PayloadInjector)
    assert injector.original_url == simple_url


# ============================================================
# Test Query Parameter Injection
# ============================================================


def test_inject_query_parameter_replace(injector_with_params: PayloadInjector) -> None:
    """Test replacing a query parameter value."""
    result = injector_with_params.inject_query_parameter(
        "page", "1' OR '1'='1", "replace"
    )
    assert "page=1%27%20OR%20%271%27%3D%271" in result.url
    assert result.injection_points[0].parameter == "page"
    assert result.injection_points[0].payload == "1' OR '1'='1"
    assert result.injection_points[0].position == "replace"


def test_inject_query_parameter_prefix(injector_with_params: PayloadInjector) -> None:
    """Test prefixing a query parameter value."""
    result = injector_with_params.inject_query_parameter("page", "payload-", "prefix")
    assert "page=payload-1" in result.url or "page=payload-1" in result.url
    assert result.injection_points[0].position == "prefix"


def test_inject_query_parameter_suffix(injector_with_params: PayloadInjector) -> None:
    """Test suffixing a query parameter value."""
    result = injector_with_params.inject_query_parameter("page", "-payload", "suffix")
    assert "page=1-payload" in result.url or "page=1-payload" in result.url
    assert result.injection_points[0].position == "suffix"


def test_inject_query_parameter_append(injector_with_params: PayloadInjector) -> None:
    """Test appending to a query parameter value."""
    result = injector_with_params.inject_query_parameter(
        "page", "&extra=value", "append"
    )
    assert result.injection_points[0].position == "append"


def test_inject_query_parameter_new(injector_simple: PayloadInjector) -> None:
    """Test injecting into a non-existent query parameter."""
    result = injector_simple.inject_query_parameter("new_param", "payload", "replace")
    assert "new_param=payload" in result.url or "new_param=payload" in result.url


def test_inject_query_parameter_invalid_position(
    injector_with_params: PayloadInjector,
) -> None:
    """Test injecting with an invalid position."""
    with pytest.raises(ValueError, match="Invalid position"):
        injector_with_params.inject_query_parameter("page", "payload", "invalid")


def test_inject_multiple_query_parameters(
    injector_with_params: PayloadInjector,
) -> None:
    """Test injecting into multiple query parameters."""
    result1 = injector_with_params.inject_query_parameter(
        "page", "1' OR '1'='1", "replace"
    )
    result2 = PayloadInjector(result1.url).inject_query_parameter(
        "limit", "10' OR '1'='1", "replace"
    )
    assert "page=1%27%20OR%20%271%27%3D%271" in result2.url
    assert "limit=10%27%20OR%20%271%27%3D%271" in result2.url


# ============================================================
# Test Path Segment Injection
# ============================================================


def test_inject_path_segment_replace(injector_simple: PayloadInjector) -> None:
    """Test replacing a path segment."""
    result = injector_simple.inject_path_segment(1, "admin", "replace")
    assert "/api/admin" in result.url or "/api/admin" in result.url


def test_inject_path_segment_prefix(injector_simple: PayloadInjector) -> None:
    """Test prefixing a path segment."""
    result = injector_simple.inject_path_segment(1, "test-", "prefix")
    assert "/api/test-users" in result.url or "/api/test-users" in result.url


def test_inject_path_segment_suffix(injector_simple: PayloadInjector) -> None:
    """Test suffixing a path segment."""
    result = injector_simple.inject_path_segment(1, "-test", "suffix")
    assert "/api/users-test" in result.url or "/api/users-test" in result.url


def test_inject_path_segment_out_of_range(injector_simple: PayloadInjector) -> None:
    """Test injecting into an out-of-range path segment."""
    with pytest.raises(IndexError):
        injector_simple.inject_path_segment(10, "payload", "replace")


# ============================================================
# Test Header Injection
# ============================================================


def test_inject_header(injector_simple: PayloadInjector) -> None:
    """Test injecting into a header."""
    result = injector_simple.inject_header("X-Forwarded-For", "127.0.0.1", "replace")
    assert result.headers.get("X-Forwarded-For") == "127.0.0.1"
    assert result.injection_points[0].location == "header"


# ============================================================
# Test Cookie Injection
# ============================================================


def test_inject_cookie(injector_simple: PayloadInjector) -> None:
    """Test injecting into a cookie."""
    result = injector_simple.inject_cookie(
        "session_id", "malicious', 'value')", "replace"
    )
    assert result.cookies.get("session_id") == "malicious', 'value')"
    assert result.injection_points[0].location == "cookie"


# ============================================================
# Test Form Data Injection
# ============================================================


def test_inject_form_data(injector_simple: PayloadInjector) -> None:
    """Test injecting into form data."""
    result = injector_simple.inject_form_data("username", "admin'--", "replace")
    assert "username=admin%27--" in result.body or "username=admin'--" in result.body
    assert result.method == "POST"
    assert result.injection_points[0].location == "body"


# ============================================================
# Test JSON Payload Injection
# ============================================================


def test_inject_json_payload(injector_simple: PayloadInjector) -> None:
    """Test injecting into a JSON payload."""
    result = injector_simple.inject_json_payload(
        ["user", "name"], "admin' OR '1'='1", "replace"
    )
    assert result.json_data is not None
    assert result.json_data.get("user", {}).get("name") == "admin' OR '1'='1"
    assert result.injection_points[0].location == "json"


def test_inject_json_payload_nested(injector_simple: PayloadInjector) -> None:
    """Test injecting into a nested JSON path."""
    result = injector_simple.inject_json_payload(
        ["user", "profile", "role"], "administrator'--", "replace"
    )
    assert result.json_data is not None
    assert (
        result.json_data.get("user", {}).get("profile", {}).get("role")
        == "administrator'--"
    )


# ============================================================
# Test XML Payload Injection
# ============================================================


def test_inject_xml_payload(injector_simple: PayloadInjector) -> None:
    """Test injecting into an XML payload."""
    result = injector_simple.inject_xml_payload(
        "username", "admin' OR '1'='1", "replace"
    )
    assert result.xml_data is not None
    assert (
        "admin&apos; OR &apos;1&apos;=&apos;1" in result.xml_data
        or "admin' OR '1'='1" in result.xml_data
    )
    assert result.injection_points[0].location == "xml"


def test_inject_xml_payload_with_special_chars(
    injector_simple: PayloadInjector,
) -> None:
    """Test injecting XML payload with special characters."""
    result = injector_simple.inject_xml_payload(
        "query", "<script>alert(1)</script>", "replace"
    )
    assert result.xml_data is not None
    # XML special characters should be escaped
    assert (
        "&lt;script&gt;alert(1)&lt;/script&gt;" in result.xml_data
        or "&lt;script&gt;alert(1)&lt;/script&gt;" in result.xml_data
    )


# ============================================================
# Test Helper Methods
# ============================================================


def test_get_all_parameters(injector_with_params: PayloadInjector) -> None:
    """Test getting all parameter names."""
    params = injector_with_params.get_all_parameters()
    assert "page" in params
    assert "limit" in params


def test_get_parameter_value(injector_with_params: PayloadInjector) -> None:
    """Test getting a parameter value."""
    value = injector_with_params.get_parameter_value("page")
    assert value == "1"


def test_get_parameter_value_not_found(injector_with_params: PayloadInjector) -> None:
    """Test getting a non-existent parameter value."""
    value = injector_with_params.get_parameter_value("nonexistent")
    assert value == ""


def test_has_parameter(injector_with_params: PayloadInjector) -> None:
    """Test checking if a parameter exists."""
    assert injector_with_params.has_parameter("page") is True
    assert injector_with_params.has_parameter("nonexistent") is False


def test_reset(injector_with_params: PayloadInjector) -> None:
    """Test resetting the injector."""
    # Modify state
    injector_with_params.inject_query_parameter("page", "test", "replace")
    assert injector_with_params.get_parameter_value("page") == "test"

    # Reset
    injector_with_params.reset()
    assert injector_with_params.get_parameter_value("page") == "1"


# ============================================================
# Test Edge Cases
# ============================================================


def test_empty_parameter_value() -> None:
    """Test handling of empty parameter values."""
    url = "https://example.com/api?empty="
    injector = PayloadInjector(url)
    assert injector.get_parameter_value("empty") == ""


def test_duplicate_parameters(url_with_duplicate_params: str) -> None:
    """Test handling of duplicate parameters."""
    injector = PayloadInjector(url_with_duplicate_params)
    result = injector.inject_query_parameter("filter", "injected", "replace")
    # Should preserve both parameters
    assert "filter=injected" in result.url
    # Original duplicate should be preserved
    # Note: The behavior here depends on the implementation


def test_url_with_encoding(url_with_encoding: str) -> None:
    """Test handling of already encoded URLs."""
    injector = PayloadInjector(url_with_encoding)
    result = injector.inject_query_parameter("q", "injected", "replace")
    # Should handle encoding properly
    assert "q=injected" in result.url or "q=injected" in result.url


def test_url_with_fragment(url_with_fragment: str) -> None:
    """Test preserving fragments."""
    injector = PayloadInjector(url_with_fragment)
    result = injector.inject_query_parameter("page", "2", "replace")
    assert "#section" in result.url
    assert "page=2" in result.url


def test_url_without_parameters(injector_simple: PayloadInjector) -> None:
    """Test injecting into a URL without parameters."""
    result = injector_simple.inject_query_parameter("new", "value", "replace")
    assert "new=value" in result.url


def test_special_characters_in_payload(injector_simple: PayloadInjector) -> None:
    """Test injecting payloads with special characters."""
    payload = "' OR '1'='1' -- "
    result = injector_simple.inject_query_parameter("test", payload, "replace")
    # URL should be properly encoded
    assert (
        "test=%27%20OR%20%271%27%3D%271%27%20--%20" in result.url
        or "test=' OR '1'='1' -- " in result.url
    )


# ============================================================
# Test Deterministic Behavior
# ============================================================


def test_deterministic_output() -> None:
    """Test that identical inputs produce identical outputs."""
    url = "https://example.com?param=value"
    injector1 = PayloadInjector(url)
    injector2 = PayloadInjector(url)

    result1 = injector1.inject_query_parameter("param", "test", "replace")
    result2 = injector2.inject_query_parameter("param", "test", "replace")

    assert result1.url == result2.url


# ============================================================
# Test Immutability
# ============================================================


def test_immutability(injector_simple: PayloadInjector) -> None:
    """Test that the original URL is preserved."""
    original_url = injector_simple.original_url
    result = injector_simple.inject_query_parameter("test", "value", "replace")
    assert injector_simple.original_url == original_url
    assert result.original_url == original_url
    assert result.url != original_url


# ============================================================
# Test Integration with Multiple Injection Points
# ============================================================


def test_multiple_injection_points(injector_with_params: PayloadInjector) -> None:
    """Test applying multiple injection points."""
    # Inject into page parameter
    result1 = injector_with_params.inject_query_parameter(
        "page", "1' OR '1'='1", "replace"
    )
    injector2 = PayloadInjector(result1.url)

    # Inject into limit parameter
    result2 = injector2.inject_query_parameter("limit", "10' OR '1'='1", "replace")

    # Both injections should be present
    assert "page=1%27%20OR%20%271%27%3D%271" in result2.url
    assert "limit=10%27%20OR%20%271%27%3D%271" in result2.url
    assert len(result2.injection_points) == 1  # Only the last injection is tracked
