"""
===========================================================
Project : Sentinel AI
Module  : Security Headers Detection
File ID : RECON-HEADERS-001
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

from app.tools.http_client import http

SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
)


def analyze_headers(target: str) -> dict:
    """
    Analyze HTTP response headers.

    Returns:
        {
            "present": {},
            "missing": [],
            "server": "...",
            "powered_by": "..."
        }
    """

    result = {
        "present": {},
        "missing": [],
        "server": "",
        "powered_by": "",
    }

    response = http.get(target)

    if response is None:
        return result

    headers = response.headers

    # =====================================================
    # Server Information
    # =====================================================

    result["server"] = headers.get("Server", "")

    result["powered_by"] = headers.get(
        "X-Powered-By",
        "",
    )

    # =====================================================
    # Security Headers
    # =====================================================

    for header in SECURITY_HEADERS:
        value = headers.get(header)

        if value:
            result["present"][header] = value

        else:
            result["missing"].append(header)

    return result


# =========================================================
# Temporary Test
# =========================================================

if __name__ == "__main__":
    target = "https://bugcrowd.com"

    result = analyze_headers(target)

    print("-" * 60)
    print("Security Headers")
    print("-" * 60)

    print()

    print("Server")
    print("------")
    print(result["server"] or "Unknown")

    print()

    print("Powered By")
    print("----------")
    print(result["powered_by"] or "Hidden")

    print()

    print("Present Headers")
    print("----------------")

    if result["present"]:
        for header, value in result["present"].items():
            print(f"[+] {header}")

            print(f"    {value}")

    else:
        print("None")

    print()

    print("Missing Headers")
    print("----------------")

    if result["missing"]:
        for header in result["missing"]:
            print(f"[-] {header}")

    else:
        print("None")
