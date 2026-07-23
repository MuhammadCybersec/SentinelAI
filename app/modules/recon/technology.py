"""
===========================================================
Project : Sentinel AI
Module  : Technology Detection
File ID : RECON-TECH-001
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

from app.tools.http_client import http


def detect_technology(target: str) -> dict:
    """
    Detect common web technologies from HTTP headers.
    """

    technologies: dict[str, str] = {}

    response = http.get(target)

    if response is None:
        return technologies

    headers = response.headers

    # =====================================================
    # Server
    # =====================================================

    if "Server" in headers:
        technologies["Server"] = headers["Server"]

    # =====================================================
    # Powered By
    # =====================================================

    if "X-Powered-By" in headers:
        technologies["X-Powered-By"] = headers["X-Powered-By"]

    # =====================================================
    # ASP.NET
    # =====================================================

    if "X-AspNet-Version" in headers:
        technologies["ASP.NET"] = headers["X-AspNet-Version"]

    # =====================================================
    # CDN
    # =====================================================

    server = headers.get("Server", "").lower()

    if "cloudflare" in server:
        technologies["CDN"] = "Cloudflare"

    elif "cloudfront" in server:
        technologies["CDN"] = "CloudFront"

    elif "akamai" in server:
        technologies["CDN"] = "Akamai"

    # =====================================================
    # Framework Detection
    # =====================================================

    powered = headers.get("X-Powered-By", "").lower()

    if "php" in powered:
        technologies["Language"] = "PHP"

    elif "express" in powered:
        technologies["Framework"] = "Express.js"

    elif "asp.net" in powered:
        technologies["Framework"] = "ASP.NET"

    return technologies


# =========================================================
# Temporary Test
# =========================================================

if __name__ == "__main__":

    result = detect_technology("https://bugcrowd.com")

    print("-" * 50)
    print("Detected Technologies")
    print("-" * 50)

    if not result:

        print("Nothing detected.")

    else:

        for key, value in result.items():

            print(f"{key:15} : {value}")
