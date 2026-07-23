"""
SentinelAI SQL Injection Scanner Tests
"""

from app.modules.scanner.modules.sqli import (
    SQLFinding,
    SQLiScanner,
)

from app.modules.scanner.core.request_engine import (
    ResponseData,
)


def create_scanner() -> SQLiScanner:
    """
    Create a SQLi scanner instance for testing.
    """

    return SQLiScanner(
        target="http://example.com",
    )


def test_scanner_creation():
    """
    Verify scanner initializes correctly.
    """

    scanner = create_scanner()

    assert scanner is not None

    assert scanner.info.name == "SQL Injection"

    assert scanner.info.slug == "sqli"

    print("✓ Scanner created successfully")


def test_payload_engine():
    """
    Verify SQL payload engine.
    """

    scanner = create_scanner()

    payloads = scanner.get_all_payloads()

    assert isinstance(payloads, list)

    assert len(payloads) > 0

    assert scanner.payload_count() == len(payloads)

    print(f"✓ Payload count: {len(payloads)}")


def test_dbms_detection():
    """
    Verify DBMS fingerprint detection.
    """

    scanner = create_scanner()

    samples = {
        "MySQL": (
            "You have an error in your SQL syntax",
            "MySQL",
        ),
        "PostgreSQL": (
            "PG::SyntaxError",
            "PostgreSQL",
        ),
        "Microsoft SQL Server": (
            "Unclosed quotation mark",
            "Microsoft SQL Server",
        ),
        "Oracle": (
            "ORA-00933",
            "Oracle",
        ),
        "SQLite": (
            "SQLiteException",
            "SQLite",
        ),
    }

    for name, (body, expected) in samples.items():

        detected = scanner.detect_dbms(body)

        assert detected == expected

        print(f"✓ {name} detected")


def test_waf_detection():
    """
    Verify WAF fingerprint detection.
    """

    class FakeResponse:
        def __init__(self, text="", headers=None):
            self.text = text
            self.headers = headers or {}

    scanner = create_scanner()

    samples = [
        (
            "Cloudflare",
            FakeResponse(
                text="Attention Required",
                headers={"CF-Ray": "12345"},
            ),
        ),
        (
            "Akamai",
            FakeResponse(
                text="Akamai Bot Manager",
            ),
        ),
        (
            "AWS WAF",
            FakeResponse(
                headers={"x-amzn-requestid": "abcd"},
            ),
        ),
        (
            "Imperva",
            FakeResponse(
                headers={"X-Iinfo": "abcdef"},
            ),
        ),
        (
            "Sucuri",
            FakeResponse(
                text="Access Denied - Sucuri Website Firewall",
            ),
        ),
        (
            "ModSecurity",
            FakeResponse(
                text="ModSecurity: Access denied",
            ),
        ),
    ]

    for expected, response in samples:

        detected = scanner.detect_waf(response)

        assert detected == expected

        print(f"✓ {expected} detected")


def test_boolean_detection():
    """
    Verify Boolean-Based SQL Injection detection.
    """

    scanner = create_scanner()

    # Same response (should NOT detect)
    assert (
        scanner.detect_boolean_sqli(
            "Welcome User",
            "Welcome User",
        )
        is False
    )

    # Completely different response (should detect)
    assert (
        scanner.detect_boolean_sqli(
            "Welcome Administrator",
            "Access Denied",
        )
        is True
    )

    # Empty responses
    assert (
        scanner.detect_boolean_sqli(
            "",
            "",
        )
        is False
    )

    print("✓ Boolean SQLi detection passed")


# ======================================================
# Confidence Score
# ======================================================


def test_confidence() -> None:

    scanner = SQLiScanner(
        "http://localhost",
    )

    score = scanner.calculate_confidence(
        has_error=True,
        boolean_detected=True,
        time_detected=False,
        dbms="MySQL",
    )

    assert score == 0.80

    print(
        "✓ Confidence calculation passed",
    )


# ======================================================
# Time-Based Detection
# ======================================================


def test_time_detection() -> None:

    scanner = SQLiScanner(
        "http://localhost",
    )

    assert (
        scanner.detect_time_sqli(
            1.0,
            6.2,
        )
        is True
    )

    assert (
        scanner.detect_time_sqli(
            1.0,
            3.0,
        )
        is False
    )

    print(
        "✓ Time-Based detection passed",
    )


# ======================================================
# Merge Findings
# ======================================================


def test_merge_findings() -> None:

    scanner = SQLiScanner(
        "http://localhost",
    )

    a = SQLFinding(
        vulnerable=True,
        url="http://localhost",
        payload="' OR 1=1--",
        technique="Error-Based",
        dbms="MySQL",
    )

    b = SQLFinding(
        vulnerable=True,
        url="http://localhost",
        payload="' OR 1=1--",
        technique="Boolean-Based",
        dbms="MySQL",
    )

    merged = scanner.merge_findings(
        [
            a,
            b,
        ]
    )

    assert (
        len(
            merged,
        )
        == 1
    )

    print(
        "✓ Merge findings passed",
    )


# ======================================================
# Enrich Finding
# ======================================================


def test_enrich_finding() -> None:

    scanner = SQLiScanner(
        "http://localhost",
    )

    finding = SQLFinding(
        vulnerable=True,
    )

    finding = scanner.enrich_finding(
        finding,
    )

    assert finding.cwe == "CWE-89"

    assert "OWASP" in finding.owasp

    assert finding.cvss == "CVSS v3.1"

    assert (
        len(
            finding.references,
        )
        > 0
    )

    print(
        "✓ Enrich finding passed",
    )


# ======================================================
# Safe Request
# ======================================================


def test_safe_request() -> None:

    scanner = SQLiScanner(
        "http://localhost",
    )

    # --------------------------------------------------
    # Mock send_request()
    # --------------------------------------------------

    def mock_send_request(
        payload: str = "",
        retries: int = 3,
    ) -> ResponseData:

        return ResponseData(
            status_code=200,
            url="http://localhost",
            body="OK",
            headers={},
            cookies={},
            elapsed=0.05,
            content_length=2,
            content_type="text/html",
            server="TestServer",
            title="Home",
        )

    scanner.send_request = mock_send_request

    # --------------------------------------------------
    # Execute
    # --------------------------------------------------

    response = scanner.safe_request()

    # --------------------------------------------------
    # Assertions
    # --------------------------------------------------

    assert response is not None

    assert response.status_code == 200

    assert response.body == "OK"

    assert scanner.statistics["requests"] == 1

    assert scanner.requests_sent == 1

    assert scanner.responses_received == 1

    print(
        "✓ Safe request passed",
    )


# ======================================================
# Payload Execution
# ======================================================


def test_payload_execution() -> None:

    scanner = SQLiScanner(
        "http://localhost",
    )

    # --------------------------------------------------
    # Mock Response
    # --------------------------------------------------

    response = ResponseData(
        status_code=200,
        url="http://localhost",
        body="SQL syntax error near MySQL",
        headers={},
        cookies={},
        elapsed=0.10,
        content_length=120,
        content_type="text/html",
        server="Apache",
        title="Home",
    )

    # --------------------------------------------------
    # Mock safe_request()
    # --------------------------------------------------

    scanner.safe_request = lambda payload="": response

    # --------------------------------------------------
    # Mock evaluate_response()
    # --------------------------------------------------

    finding = SQLFinding(
        vulnerable=True,
        url="http://localhost",
        payload="'",
        technique="Error-Based",
        dbms="MySQL",
    )

    scanner.evaluate_response = lambda url, payload, response: finding

    # --------------------------------------------------
    # Mock Boolean Pair
    # --------------------------------------------------

    scanner.get_boolean_payload_pair = lambda: (
        "' OR 1=1--",
        "' OR 1=2--",
    )

    scanner.validate_boolean_detection = lambda true_response, false_response: True

    # --------------------------------------------------
    # Execute
    # --------------------------------------------------

    result = scanner.test_payload("'")

    # --------------------------------------------------
    # Assertions
    # --------------------------------------------------

    assert result is not None

    assert result.technique == "Boolean-Based"

    assert "Boolean SQL Injection confirmed." in result.evidence

    print(
        "✓ Payload execution passed",
    )


# ======================================================
# Time Payload Execution
# ======================================================


def test_time_payload_execution() -> None:

    scanner = SQLiScanner(
        "http://localhost",
    )

    # --------------------------------------------------
    # Mock Response
    # --------------------------------------------------

    response = ResponseData(
        status_code=200,
        url="http://localhost",
        body="OK",
        headers={},
        cookies={},
        elapsed=5.20,
        content_length=2,
        content_type="text/html",
        server="Apache",
        title="Home",
    )

    # --------------------------------------------------
    # Mock Baseline
    # --------------------------------------------------

    scanner.get_baseline_time = lambda: 0.20

    # --------------------------------------------------
    # Mock Request
    # --------------------------------------------------

    scanner.safe_request = lambda payload="": response

    # --------------------------------------------------
    # Mock Time Detection
    # --------------------------------------------------

    scanner.detect_time_sqli = lambda baseline_time, injected_time, threshold=5: True

    # --------------------------------------------------
    # Mock Analyzer
    # --------------------------------------------------

    original_analyze = scanner.analyzer.analyze

    scanner.analyzer.analyze = lambda response, payload="": original_analyze(
        response,
        payload,
    )

    scanner.detected_dbms = "MySQL"

    # --------------------------------------------------
    # Execute
    # --------------------------------------------------

    finding = scanner.test_time_payload(
        "'; WAITFOR DELAY '0:0:5'--",
    )

    # --------------------------------------------------
    # Assertions
    # --------------------------------------------------

    assert finding is not None

    assert finding.vulnerable is True

    assert finding.technique == "Time-Based"

    assert finding.dbms == "MySQL"

    assert len(finding.evidence) == 3

    print(
        "✓ Time payload execution passed",
    )


# ======================================================
# Full Scan
# ======================================================


def test_scan_execution() -> None:

    scanner = SQLiScanner(
        "http://localhost",
    )

    # --------------------------------------------------
    # Initial Request
    # --------------------------------------------------

    response = ResponseData(
        status_code=200,
        url="http://localhost",
        body="OK",
        headers={},
        cookies={},
        elapsed=0.10,
        content_length=2,
        content_type="text/html",
        server="Apache",
        title="Home",
    )

    scanner.safe_request = lambda payload="": response

    # --------------------------------------------------
    # Payloads
    # --------------------------------------------------

    scanner.get_production_payloads = lambda response=None: [
        "'",
        '"',
    ]

    scanner.get_time_payloads = lambda dbms=None: []

    # --------------------------------------------------
    # Mock test_payload
    # --------------------------------------------------

    finding = SQLFinding()

    finding.vulnerable = True

    finding.payload = "'"

    finding.url = scanner.target

    finding.technique = "Error-Based"

    scanner.test_payload = lambda payload: finding

    scanner.merge_findings = lambda findings: findings

    scanner.enrich_finding = lambda finding: finding

    # --------------------------------------------------
    # Execute
    # --------------------------------------------------

    results = scanner.scan()

    # --------------------------------------------------
    # Assertions
    # --------------------------------------------------

    assert (
        len(
            results,
        )
        == 2
    )

    assert scanner.statistics["payloads"] == 2

    assert scanner.statistics["requests"] >= 1

    print(
        "✓ Full scan passed",
    )


if __name__ == "__main__":

    test_scanner_creation()
    test_payload_engine()
    test_dbms_detection()
    test_waf_detection()
    test_boolean_detection()
    test_confidence()
    test_time_detection()
    test_merge_findings()
    test_enrich_finding()
    test_safe_request()
    test_payload_execution()
    print(
        "\n🎉 All SQLi unit tests passed!",
    )
