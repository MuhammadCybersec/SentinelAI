"""
===========================================================
Project : Sentinel AI
Module  : JavaScript Endpoint Discovery
File ID : RECON-JS-ENDPOINTS-001
Version : 1.1.0
===========================================================
"""

from __future__ import annotations

import re

from app.tools.http_client import http

PATTERN = re.compile(r'["\'](' r"/[A-Za-z0-9_\-./?=&%]+" r'|https?://[^"\']+' r')["\']')


def discover_js_endpoints(js_files: list[str]) -> list[str]:

    endpoints = set()

    for js in js_files:

        print(f"[+] Downloading {js}")

        response = http.get(js)

        if response is None:
            print("    Request Failed")
            continue

        print("    Status:", response.status_code)

        if response.status_code != 200:
            continue

        print("    Size:", len(response.text))

        matches = PATTERN.findall(response.text)

        print("    Matches:", len(matches))

        for m in matches:
            endpoints.add(m)

    return sorted(endpoints)


if __name__ == "__main__":

    from app.modules.recon.javascript import discover_javascript

    files = discover_javascript("https://bugcrowd.com")

    print()

    print("JavaScript Files:", len(files))

    print()

    endpoints = discover_js_endpoints(files)

    print()

    print("Endpoints:", len(endpoints))

    print()

    for endpoint in endpoints[:100]:
        print(endpoint)
