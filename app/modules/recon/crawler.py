"""
===========================================================
Project : Sentinel AI
Module  : Web Crawler
File ID : RECON-CRAWLER-001
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from app.modules.recon.url_normalizer import normalize_url
from app.tools.http_client import http


def crawl_target(
    target: str,
    session=None,
    max_links: int = 500,
) -> list[str]:
    """
    Crawl a target webpage and collect internal links.

    Returns:
        List of normalized internal URLs.
    """

    discovered: set[str] = set()

    try:

        # --------------------------------
        # Session request
        # --------------------------------

        if session is not None:

            print("[DEBUG] Session mode enabled")

            response = session.get(
                target,
                timeout=20,
                allow_redirects=True,
            )

        else:

            # print("[DEBUG] Normal mode enabled")

            response = http.get(
                target,
                timeout=20,
            )

        # --------------------------------
        # Debug output
        # --------------------------------

        # print("[DEBUG] Requested URL :", target)
        # print("[DEBUG] Response URL  :", response.url)
        # print("[DEBUG] Status Code   :", response.status_code)

        if response is None:
            print("[DEBUG] Response is None")
            return []

        if response.status_code != 200:
            print("[DEBUG] Invalid status code")
            return []

        soup = BeautifulSoup(
            response.text,
            "html.parser",
        )

        links = soup.find_all("a", href=True)

        # print(f"[DEBUG] Total links found: {len(links)}")

        base_domain = urlparse(response.url).netloc

        for tag in links:

            href = str(tag["href"]).strip()

            if not href:
                continue

            absolute = urljoin(
                response.url,
                href,
            )

            absolute = normalize_url(
                absolute,
            )

            parsed = urlparse(
                absolute,
            )

            if parsed.scheme not in (
                "http",
                "https",
            ):
                continue

            if parsed.netloc != base_domain:
                continue

            discovered.add(
                absolute,
            )

            if len(discovered) >= max_links:
                break

        # print(f"[DEBUG] Internal URLs: {len(discovered)}")

        return sorted(
            discovered,
        )

    except Exception as e:

        print(f"[CRAWLER ERROR] {e}")

        return []


# ==========================================================
# Temporary Test
# ==========================================================

if __name__ == "__main__":
    urls = crawl_target("https://bugcrowd.com")

    print(f"Internal URLs: {len(urls)}")

    for url in urls:
        print(url)
