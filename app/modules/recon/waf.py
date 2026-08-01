"""
===========================================================
Project : Sentinel AI
Module  : Web Application Firewall Detection
File ID : RECON-WAF-001
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

from app.tools.http_client import http

# ==========================================================
# Known WAF Signatures
# ==========================================================

WAF_SIGNATURES = {
    "Cloudflare": [
        "cf-ray",
        "cf-cache-status",
        "cloudflare",
    ],
    "AWS WAF": [
        "x-amzn-requestid",
        "x-amz-cf-id",
        "cloudfront",
    ],
    "Akamai": [
        "akamai",
        "akamaighost",
    ],
    "Imperva": [
        "incap_ses",
        "visid_incap",
        "x-iinfo",
    ],
    "Sucuri": [
        "x-sucuri-id",
        "x-sucuri-cache",
    ],
    "F5 BIG-IP": [
        "bigip",
        "f5avr",
    ],
    "Fastly": [
        "fastly",
        "x-served-by",
    ],
    "StackPath": [
        "stackpath",
    ],
    "Barracuda": [
        "barra_counter_session",
    ],
    "FortiWeb": [
        "fortiweb",
    ],
    "Azure Front Door": [
        "x-azure-ref",
    ],
    "Reblaze": [
        "rbzid",
    ],
    "ModSecurity": [
        "mod_security",
        "modsecurity",
    ],
}


def detect_waf(target: str) -> dict:
    """
    Detect Web Application Firewall.

    Returns:
    {
        "detected": bool,
        "vendor": "...",
        "confidence": "...",
        "evidence": []
    }
    """

    result = {
        "detected": False,
        "vendor": "Unknown",
        "confidence": "Low",
        "evidence": [],
    }

    response = http.get(target)

    if response is None:
        return result

    headers = {k.lower(): v.lower() for k, v in response.headers.items()}

    cookies = response.cookies

    server = headers.get("server", "")

    # ======================================================
    # Detect WAF
    # ======================================================

    for vendor, signatures in WAF_SIGNATURES.items():
        evidence = []

        for sig in signatures:
            # Header name
            if sig in headers:
                evidence.append(f"Header: {sig}")

            # Header value
            elif sig in server:
                evidence.append(f"Server: {server}")

            # Cookie
            else:
                for cookie in cookies:
                    if sig in cookie.name.lower():
                        evidence.append(f"Cookie: {cookie.name}")

        if evidence:
            result["detected"] = True
            result["vendor"] = vendor
            result["confidence"] = "High"
            result["evidence"] = evidence

            return result

    return result


# ==========================================================
# Temporary Test
# ==========================================================

if __name__ == "__main__":
    target = "https://bugcrowd.com"

    result = detect_waf(target)

    print("-" * 60)
    print("WAF Detection")
    print("-" * 60)

    print()

    print("Detected   :", result["detected"])
    print("Vendor     :", result["vendor"])
    print("Confidence :", result["confidence"])

    print()

    print("Evidence")
    print("--------")

    if result["evidence"]:
        for item in result["evidence"]:
            print(item)

    else:
        print("None")
