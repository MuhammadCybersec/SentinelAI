"""
===========================================================
Project : Sentinel AI
Module  : HTTP Methods Detection
File ID : RECON-HTTP-001
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

from app.tools.http_client import http

COMMON_METHODS = (
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
)


def detect_http_methods(target: str) -> list[str]:
    """
    Detect supported HTTP methods.
    """

    supported: list[str] = []

    for method in COMMON_METHODS:
        try:
            response = http.session.request(
                method=method,
                url=target,
                timeout=10,
                allow_redirects=False,
            )

            if response.status_code not in (
                405,
                501,
            ):
                supported.append(method)

        except Exception:
            continue

    return supported


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":
    target = "https://bugcrowd.com"

    methods = detect_http_methods(target)

    print("-" * 60)
    print("Supported HTTP Methods")
    print("-" * 60)
    print()

    for method in methods:
        print(method)
