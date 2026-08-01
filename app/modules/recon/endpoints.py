"""
===========================================================
Project : Sentinel AI
Module  : Endpoint Inventory
File ID : RECON-ENDPOINTS-001
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

from app.modules.recon.api_discovery import discover_api
from app.modules.recon.crawler import crawl_target
from app.modules.recon.javascript import discover_javascript
from app.modules.recon.js_endpoints import discover_js_endpoints
from app.modules.recon.wayback import collect_wayback_urls


def collect_endpoints(target: str) -> list[str]:
    """
    Collect endpoints from all recon sources.
    """

    endpoints: set[str] = set()

    # =====================================================
    # Wayback
    # =====================================================

    print("[+] Collecting Wayback URLs...")

    try:
        for url in collect_wayback_urls(target):
            endpoints.add(url)
    except Exception:
        pass

    # =====================================================
    # Crawler
    # =====================================================

    print("[+] Crawling Target...")

    try:
        for url in crawl_target(target):
            endpoints.add(url)
    except Exception:
        pass

    # =====================================================
    # JavaScript
    # =====================================================

    print("[+] Parsing JavaScript...")

    try:
        js_files = discover_javascript(target)

        for endpoint in discover_js_endpoints(js_files):
            endpoints.add(endpoint)

    except Exception:
        pass

    # =====================================================
    # API Discovery
    # =====================================================

    print("[+] Discovering APIs...")

    try:
        fake_status = 404
        fake_length = 0

        api_results = discover_api(
            target,
            fake_status,
            fake_length,
        )

        for item in api_results:
            if isinstance(item, dict):
                url = item.get("url")

                if url:
                    endpoints.add(url)

    except Exception:
        pass

    return sorted(endpoints)


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":
    TARGET = "https://bugcrowd.com"

    result = collect_endpoints(TARGET)

    print()
    print("=" * 60)
    print("Endpoint Inventory")
    print("=" * 60)
    print(f"Total Endpoints: {len(result)}")
    print()

    for endpoint in result[:50]:
        print(endpoint)
