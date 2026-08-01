"""
===========================================================
Project : Sentinel AI
Module  : Wayback URL Collector
File ID : RECON-WAYBACK-001
Version : 1.1.0
===========================================================
"""

from app.modules.recon.url_normalizer import normalize_url
from app.tools.http_client import http

WAYBACK_API = "https://web.archive.org/cdx/search/cdx"

STATIC_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".css",
    ".js",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".map",
    ".mp4",
    ".mp3",
    ".avi",
    ".mov",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
)

STATIC_PATHS = (
    "/assets/",
    "/images/",
    "/img/",
    "/fonts/",
    "/css/",
    "/js/",
    "/static/",
    "/media/",
)


def collect_wayback_urls(domain: str) -> list[str]:
    """
    Collect archived URLs from the Internet Archive Wayback Machine.
    """

    response = http.get(
        WAYBACK_API,
        params={
            "url": f"{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "filter": "statuscode:200",
            "limit": "5000",
        },
        timeout=60,
    )

    if response is None:
        return []

    if response.status_code != 200:
        return []

    try:
        data = response.json()
    except Exception:
        return []

    urls: set[str] = set()

    for row in data:
        if not row:
            continue

        if isinstance(row, list):
            url = row[0]
        else:
            url = row

        if not isinstance(url, str):
            continue

        if url == "original":
            continue

        url = normalize_url(url)

        if not url:
            continue

        # Invalid URLs
        if "%22" in url:
            continue

        if "data:image" in url:
            continue

        if len(url) > 300:
            continue

        # Ignore static files
        if url.lower().endswith(STATIC_EXTENSIONS):
            continue

        # Ignore static folders
        if any(path in url.lower() for path in STATIC_PATHS):
            continue

        urls.add(url)

    return sorted(urls)


# ======================================================
# Temporary Test
# ======================================================

if __name__ == "__main__":
    urls = collect_wayback_urls("bugcrowd.com")

    print(f"Total URLs: {len(urls)}")

    for url in urls[:20]:
        print(url)
