"""
===========================================================
Project : Sentinel AI
Module  : Recon Engine
File ID : ENGINE-RECON-001
Version : 1.0.0
===========================================================

Description:
Main reconnaissance engine responsible for executing
all recon modules and collecting their results.

===========================================================
"""

from __future__ import annotations

from app.core.logger import sentinel_logger

from app.modules.recon import TargetValidator

from app.modules.recon.crawler import crawl_target
from app.modules.recon.wayback import collect_wayback_urls
from app.modules.recon.javascript import discover_javascript
from app.modules.recon.js_endpoints import discover_js_endpoints
from app.modules.recon.js_secrets import discover_js_secrets
from app.modules.recon.parameter_discovery import discover_parameters
from app.modules.recon.api_discovery import discover_api
from app.modules.recon.headers import analyze_headers
from app.modules.recon.technology import detect_technology
from app.modules.recon.waf import detect_waf
from app.modules.recon.endpoints import collect_endpoints


class ReconEngine:
    """
    Executes every reconnaissance module.
    """

    def __init__(self) -> None:

        self.results: dict = {}

    # =====================================================
    # Run Recon
    # =====================================================

    def run(self, target: str) -> dict:

        sentinel_logger.info(f"Starting Recon: {target}")

        if not TargetValidator.is_valid(target):

            raise ValueError(f"Invalid target: {target}")

        self.results = {
            "target": target,
            "crawler": [],
            "wayback": [],
            "javascript": [],
            "js_endpoints": [],
            "js_secrets": [],
            "parameters": {},
            "api": [],
            "headers": {},
            "technology": {},
            "waf": {},
            "inventory": [],
        }

        return self.results


# =========================================================
# Temporary Test
# =========================================================

if __name__ == "__main__":

    engine = ReconEngine()

    result = engine.run("https://bugcrowd.com")

    print()

    print("Recon Engine Ready")

    print(result.keys())
