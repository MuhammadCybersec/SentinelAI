"""
===========================================================
Project : Sentinel AI
Module  : JavaScript Discovery
File ID : RECON-JS-001
Version : 1.1.0
===========================================================
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from app.tools.http_client import http

SCRIPT_PATTERN = re.compile(
    r'<script[^>]+src=["\'](.*?)["\']',
    re.IGNORECASE,
)


def discover_javascript(target: str) -> list[str]:
    """
    Discover JavaScript files from a target webpage.
    """

    response = http.get(
        target,
        allow_redirects=True,
        timeout=20,
    )

    if response is None:
        return []

    if response.status_code != 200:
        return []

    html = response.text

    matches = SCRIPT_PATTERN.findall(html)

    js_files: set[str] = set()

    for src in matches:

        if not src:
            continue

        js_url = urljoin(response.url, src)

        if not js_url.lower().startswith(("http://", "https://")):
            continue

        if not js_url.lower().endswith(".js"):
            continue

        js_files.add(js_url)

    return sorted(js_files)


# ======================================================
# Temporary Test
# ======================================================

if __name__ == "__main__":

    files = discover_javascript("https://bugcrowd.com")

    print(f"JavaScript Files: {len(files)}")

    for file in files:
        print(file)
