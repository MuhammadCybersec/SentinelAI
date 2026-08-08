"""
===========================================================
Project : Sentinel AI
Module  : Parameter Discovery
File ID : RECON-PARAM-001
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse


def discover_parameters(urls: list[str]) -> dict[str, list[str]]:
    """
    Discover GET parameters from a list of URLs.

    Example:
        https://site.com/search?q=test&page=2

    Returns:
        {
            "q": [
                "https://site.com/search?q=test&page=2"
            ],
            "page": [
                "https://site.com/search?q=test&page=2"
            ]
        }
    """

    parameters: dict[str, list[str]] = {}

    for url in urls:
        try:
            parsed = urlparse(url)

            if not parsed.query:
                continue

            query = parse_qs(parsed.query)

            for parameter in query:
                if parameter not in parameters:
                    parameters[parameter] = []

                if url not in parameters[parameter]:
                    parameters[parameter].append(url)

        except Exception:
            continue

    return parameters


# ==========================================================
# Temporary Test
# ==========================================================

if __name__ == "__main__":
    urls = [
        "https://bugcrowd.com/search?q=test&page=1",
        "https://bugcrowd.com/login?redirect=dashboard",
        "https://bugcrowd.com/api?id=15&user=admin",
        "https://bugcrowd.com/about",
    ]

    result = discover_parameters(urls)

    print("-" * 50)

    print("Discovered Parameters")

    print("-" * 50)

    for parameter, url_list in result.items():
        print(parameter)

        for url in url_list:
            print("   ", url)
