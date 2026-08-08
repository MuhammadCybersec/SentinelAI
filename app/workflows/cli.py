"""
===========================================================
Project : Sentinel AI
Module  : Interactive CLI
File ID : CLI-001
Version : 0.1.0
===========================================================
"""

import json
import logging

from app.core.logger import sentinel_logger

logger = logging.getLogger(__name__)


class CLI:
    def __init__(self, manager):
        self.manager = manager

    def start(self):
        sentinel_logger.info("CLI Started")

        print("\n")
        print("=" * 60)
        print(" Sentinel AI Interactive Console ")
        print(" Type 'exit' to quit.")
        print("=" * 60)

        while True:
            try:
                command = input("\nSentinelAI> ").strip()

                if command.lower() == "exit":
                    print("Goodbye!")
                    break

                if command == "":
                    continue

                result = self.manager.handle(command)

                # ============================================
                # Project Object
                # ============================================

                if hasattr(result, "id"):
                    if command.lower().startswith("create"):
                        print("\nProject Created Successfully")
                    elif command.lower() == "current project":
                        print("\nCurrent Project")
                    else:
                        print("\nProject Information")

                    print("-" * 40)
                    print(f"ID          : {result.id}")
                    print(f"Name        : {result.name}")
                    print(f"Target      : {result.target}")
                    print(f"Description : {result.description}")

                # ============================================
                # List of Projects
                # ============================================

                elif isinstance(result, list):
                    print("\nProjects")
                    print("-" * 60)

                    if not result:
                        print("No projects found.")
                    else:
                        for project in result:
                            print(f"ID          : {project.id}")
                            print(f"Name        : {project.name}")
                            print(f"Target      : {project.target}")
                            print(f"Description : {project.description}")
                            print("-" * 60)

                # ============================================
                # Recon Report - CLEAN (No raw dict dumps)
                # ============================================

                elif isinstance(result, dict):
                    # Check if it's a help/commands response
                    if "commands" in result:
                        print("\nAvailable Commands")
                        print("-" * 40)
                        for cmd in result["commands"]:
                            print(f"  - {cmd}")
                        continue

                    # Check if it's a scan report
                    if "summary" in result and "recon" in result:
                        self._print_scan_report(result)
                        continue

                    # Check if it's recon results
                    if "urls" in result or "crawler" in result:
                        self._print_recon_report(result)
                        continue

                    # Default: print clean key-value pairs
                    print("\n" + "=" * 60)
                    for key, value in result.items():
                        if key in ["headers", "dns_records", "waf", "http_methods"]:
                            continue
                        if isinstance(value, (list, dict)):
                            continue
                        print(f"{key.capitalize():12}: {value}")
                    print("=" * 60)

                # ============================================
                # Normal Text Response
                # ============================================

                else:
                    print(result)

            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except Exception as e:
                logger.error(f"CLI Error: {e}")
                if logger.isEnabledFor(logging.DEBUG):
                    import traceback

                    traceback.print_exc()
                print(f"Error: {e}")

    # ==========================================================
    # CLEAN SCAN REPORT - No raw dict dumps
    # ==========================================================

    def _print_scan_report(self, report: dict) -> None:
        """Print clean scan report - NO raw dict dumps."""
        print("\n" + "=" * 60)
        print("Scan Complete")
        print("=" * 60)

        summary = report.get("summary", {})
        recon = report.get("recon", {})

        print("\nReconnaissance:")
        print(f"  URLs discovered   : {recon.get('urls', 0)}")
        print(f"  Interesting URLs  : {recon.get('interesting', 0)}")
        print(f"  Parameters found  : {recon.get('parameters', 0)}")
        print(f"  Forms discovered  : {recon.get('forms', 0)}")
        print(f"  Technology        : {recon.get('technology', 'Unknown')}")

        print("\nVulnerability Scanning:")
        print(f"  Raw findings       : {summary.get('raw_findings', 0)}")
        print(f"  VERIFIED           : {summary.get('verified', 0)}")
        print(f"  INCONCLUSIVE       : {summary.get('inconclusive', 0)}")
        print(f"  REJECTED           : {summary.get('rejected', 0)}")
        print(f"  NOT_APPLICABLE     : {summary.get('not_applicable', 0)}")
        print(f"  ERRORS             : {summary.get('verification_errors', 0)}")
        print(f"  Duplicates removed : {summary.get('duplicates_removed', 0)}")
        print(f"  Unique findings    : {summary.get('unique_findings', 0)}")

        scanner_results = report.get("scanner_results", {})
        if scanner_results:
            print("\nFindings by type:")
            for scanner, count in scanner_results.items():
                print(f"  {scanner.upper()} : {count}")

        print(f"\nDatabase saved     : {summary.get('saved_findings', 0)}")
        print(f"Errors             : {summary.get('errors', 0)}")
        print("\n" + "=" * 60)
        print("SentinelAI> Scan completed successfully")

    def _print_recon_report(self, result: dict) -> None:
        """Print clean recon report."""
        print("\n" + "=" * 60)
        print("Recon Report")
        print("=" * 60)

        urls = result.get("urls", [])
        print(f"URLs discovered   : {len(urls)}")
        print(f"Interesting URLs  : {len(result.get('interesting_urls', []))}")
        print(f"Parameters found  : {len(result.get('parameters', {}))}")
        print(f"Forms discovered  : {len(result.get('forms', []))}")

        tech = result.get("technologies", {})
        if tech:
            print(f"Technology        : {tech.get('Server', 'Unknown')}")

        waf = result.get("waf", {})
        if waf:
            print(f"WAF Detected      : {waf.get('detected', False)}")

        print("=" * 60)
