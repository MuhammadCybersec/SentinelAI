"""
===========================================================
Project : Sentinel AI
Module  : Recon Engine
File ID : RECON-ENGINE-001
Version : 1.0.0
===========================================================
"""

from __future__ import annotations
from app.modules.recon.parameter_discovery import discover_parameters
from app.modules.recon.form_discovery import discover_forms, extract_form_parameters
from app.modules.recon.api_discovery import discover_api
from app.modules.recon.crawler import crawl_target
from app.modules.recon.headers import analyze_headers
from app.modules.recon.interesting_urls import find_interesting_urls
from app.modules.recon.javascript import discover_javascript
from app.modules.recon.js_endpoints import discover_js_endpoints
from app.modules.recon.js_secrets import discover_js_secrets
from app.modules.recon.risk_scoring import score_urls
from app.modules.recon.target_validator import TargetValidator
from app.modules.recon.technology import detect_technology
from app.modules.recon.waf import detect_waf
from app.modules.recon.wayback import collect_wayback_urls
from app.modules.browser.login_manager import dvwa_login


class ReconEngine:
    """
    SentinelAI Recon Engine.
    """

    def run(self, target: str) -> dict:

        if not TargetValidator.is_valid(target):
            raise ValueError(f"Invalid target: {target}")

        # print("=" * 60)
        # print("SentinelAI Recon Engine")
        # print("=" * 60)
        # print()

        # ---------------------------------------
        # print("[1/10] Wayback...")
        wayback_urls = collect_wayback_urls(target)

        base_url = "/".join(target.split("/")[:4])
        session = dvwa_login(base_url)
        test = session.get(base_url)
        # print("After Login:", test.url)
        # ---------------------------------------
        # print("[2/10] Crawler...")
        crawled_urls = crawl_target(
            target,
            session=session,
        )

        # ---------------------------------------
        all_urls = sorted(set(wayback_urls + crawled_urls))

        # ---------------------------------------
        # print("[3/10] Interesting URLs...")
        interesting = find_interesting_urls(all_urls)

        # ---------------------------------------
        # ---------------------------------------
        # print("[4/10] Parameters & Forms...")
        parameters = discover_parameters(all_urls)

        # Discover forms from crawled URLs (limit to first 50 for performance)
        all_forms = []
        max_form_urls = 50

        for idx, url in enumerate(all_urls[:max_form_urls]):
            try:
                if session:
                    response = session.get(url, timeout=10, allow_redirects=True)
                else:
                    import requests

                    response = requests.get(url, timeout=10, allow_redirects=True)

                if response.status_code == 200:
                    forms = discover_forms(url, response.text)
                    all_forms.extend(forms)
            except Exception as e:
                print(f"[FORM] Skipped {url}: {e}")

        form_parameters = extract_form_parameters(all_forms)

        # Merge GET parameters with form parameters
        merged_parameters = parameters.copy()
        for param, urls in form_parameters.items():
            if param not in merged_parameters:
                merged_parameters[param] = []
            for url in urls:
                if url not in merged_parameters[param]:
                    merged_parameters[param].append(url)

        # print(f"[DEBUG] Forms found: {len(all_forms)}")
        # print(f"[DEBUG] Form parameters: {len(form_parameters)}")
        # print(f"[DEBUG] Total unique parameters: {len(merged_parameters)}")

        # ---------------------------------------
        # print("[5/10] JavaScript...")
        js_files = discover_javascript(target)

        # ---------------------------------------
        # print("[6/10] JS Endpoints...")
        js_endpoints = discover_js_endpoints(js_files)

        # ---------------------------------------
        # print("[7/10] JS Secrets...")
        js_secrets = discover_js_secrets(js_files)

        # ---------------------------------------
        # print("[8/10] Technologies...")
        technologies = detect_technology(target)

        # ---------------------------------------
        # print("[9/10] Headers / WAF...")

        headers = analyze_headers(target)

        waf = detect_waf(target)

        # ---------------------------------------
        # print("[10/10] Risk Scoring...")

        risks = score_urls(all_urls)

        fake_status = 404
        fake_length = 0

        api = discover_api(
            target,
            fake_status,
            fake_length,
        )

        return {
            "target": target,
            "urls": all_urls,
            "interesting_urls": interesting,
            "parameters": merged_parameters,
            "forms": all_forms,
            "form_parameters": form_parameters,
            "javascript": js_files,
            "js_endpoints": js_endpoints,
            "js_secrets": js_secrets,
            "technologies": technologies,
            "headers": headers,
            "waf": waf,
            "api": api,
            "risk": risks,
        }


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":
    engine = ReconEngine()

    result = engine.run("https://bugcrowd.com")

    print()
    print("=" * 60)
    print("Recon Summary")
    print("=" * 60)

    print("URLs              :", len(result["urls"]))
    print("Interesting URLs  :", len(result["interesting_urls"]))
    print("Parameters        :", len(result["parameters"]))
    print("JavaScript Files  :", len(result["javascript"]))
    print("JS Endpoints      :", len(result["js_endpoints"]))
    print("JS Secrets        :", len(result["js_secrets"]))
    print("APIs              :", len(result["api"]))
    print("Risk Entries      :", len(result["risk"]))
