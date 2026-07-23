"""
===========================================================
Project : Sentinel AI
Module  : API Discovery
File ID : RECON-API-001
Version : 1.0.0
===========================================================
"""

from app.tools.http_client import http

COMMON_API_PATHS = [
    "/swagger",
    "/swagger/",
    "/swagger-ui",
    "/swagger-ui/",
    "/swagger-ui.html",
    "/api-docs",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/api",
    "/api/",
    "/api/v1",
    "/api/v2",
    "/rest",
    "/rest/",
]


def discover_api(
    base_url: str,
    fake_status: int,
    fake_length: int,
) -> list[dict]:
    """
    Discover common API endpoints.

    Returns:
        [
            {
                "path": "/api",
                "url": "https://example.com/api",
                "status": 200,
            }
        ]
    """

    findings: list[dict] = []

    base_url = base_url.rstrip("/")

    for path in COMMON_API_PATHS:

        url = base_url + path

        response = http.get(url)

        if response is None:
            continue

        length = len(response.text)

        # ==========================================
        # Soft 404 Detection
        # ==========================================

        if response.status_code == fake_status and abs(length - fake_length) < 100:
            continue

        # ==========================================
        # Ignore Redirects
        # ==========================================

        if response.history:
            continue

        # ==========================================
        # Valid API Responses
        # ==========================================

        if response.status_code in (
            200,
            401,
            403,
        ):

            findings.append(
                {
                    "path": path,
                    "url": response.url,
                    "status": response.status_code,
                }
            )

    return findings


# ==========================================================
# Temporary Test
# ==========================================================

if __name__ == "__main__":

    TARGET = "https://bugcrowd.com"

    results = discover_api(
        TARGET,
        fake_status=404,
        fake_length=0,
    )

    print()

    print("API Discovery")
    print("-" * 40)

    if not results:
        print("No API endpoints found.")

    else:

        for item in results:

            print(f'{item["status"]:<4} {item["path"]}')
            print(f'      {item["url"]}')
