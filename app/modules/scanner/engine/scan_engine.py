"""
SentinelAI Scan Engine
"""

import logging
from typing import List, Optional, Any, Dict

from app.modules.scanner.core.finding_processor import FindingProcessor

logger = logging.getLogger(__name__)


class ScanEngine:
    """Scan Engine for running vulnerability scanners."""

    def __init__(self, session=None, verbose: bool = False):
        self.session = session
        self.verbose = verbose
        self.scanners = []
        self.findings = []
        self.processed_findings = []
        self.statistics = {
            "total_scanners": 0,
            "scanners_run": 0,
            "findings_found": 0,
            "errors": 0,
        }
        self._logger = logging.getLogger(__name__)
        self.processor = FindingProcessor(verbose=verbose)

        # Register default scanners
        self._register_default_scanners()

    # ==========================================================
    # SCANNER REGISTRATION - Clean output
    # ==========================================================

    def _register_scanner(self, name: str, module_path: str, class_name: str):
        """Safely register a scanner with isolated import."""
        try:
            module = __import__(module_path, fromlist=[class_name])
            scanner_class = getattr(module, class_name)
            self.register_scanner(name, scanner_class)
            self._logger.info(f"Registered scanner: {name}")
        except ImportError as e:
            print(f"[ScanEngine] ⚠️ WARNING: {name} unavailable: {e}")
            self._logger.warning(f"Failed to import {name}: {e}")
        except AttributeError as e:
            print(
                f"[ScanEngine] ⚠️ WARNING: {name} - class {class_name} not found: {e}"
            )
            self._logger.warning(f"Class {class_name} not found in {module_path}: {e}")
        except Exception as e:
            print(f"[ScanEngine] ⚠️ WARNING: {name} registration failed: {e}")
            self._logger.error(f"Unexpected error registering {name}: {e}")

    def _register_default_scanners(self):
        """Register all default vulnerability scanners."""
        print("[ScanEngine] Registering vulnerability scanners...")

        scanners = [
            ("sqli", "app.modules.scanner.modules.sqli", "SQLiScanner"),
            ("xss", "app.modules.scanner.modules.xss_scanner", "XSSScanner"),
            ("ssrf", "app.modules.scanner.modules.ssrf_scanner", "SSRFScanner"),
            ("lfi", "app.modules.scanner.modules.lfi_scanner", "LFIScanner"),
            ("rfi", "app.modules.scanner.modules.rfi_scanner", "RFIScanner"),
            ("idor", "app.modules.scanner.modules.idor", "IDORScanner"),
            (
                "open_redirect",
                "app.modules.scanner.modules.open_redirect",
                "OpenRedirectScanner",
            ),
            (
                "cmd_injection",
                "app.modules.scanner.modules.cmd_injection",
                "CommandInjectionScanner",
            ),
            ("crlf", "app.modules.scanner.modules.crlf", "CRLFScanner"),
            ("cors", "app.modules.scanner.modules.cors", "CORSScanner"),
            ("csrf", "app.modules.scanner.modules.csrf", "CSRFScanner"),
            (
                "clickjacking",
                "app.modules.scanner.modules.clickjacking",
                "ClickjackingScanner",
            ),
            (
                "file_upload",
                "app.modules.scanner.modules.file_upload",
                "FileUploadScanner",
            ),
            ("jwt", "app.modules.scanner.modules.jwt", "JWTScanner"),
            (
                "host_header",
                "app.modules.scanner.modules.host_header",
                "HostHeaderScanner",
            ),
            (
                "prototype_pollution",
                "app.modules.scanner.modules.prototype_pollution",
                "PrototypePollutionScanner",
            ),
        ]

        for name, module_path, class_name in scanners:
            self._register_scanner(name, module_path, class_name)

        total = len(self.scanners)
        print(f"[ScanEngine] Registered {total} vulnerability scanners")
        self.statistics["total_scanners"] = total

    def register_scanner(self, scanner_name: str, scanner_class):
        """Register a scanner with duplicate check."""
        for s in self.scanners:
            if s["name"] == scanner_name:
                return
        self.scanners.append({"name": scanner_name, "class": scanner_class})
        self.statistics["total_scanners"] = len(self.scanners)

    # ==========================================================
    # ENRICH FINDING WITH RESPONSE
    # ==========================================================

    def _enrich_finding_with_response(self, finding: Dict) -> None:
        """
        Enrich finding with full response data.

        FIX: Ensure evidence includes the actual response body
        for LFI/RFI verification.
        """
        # If evidence is empty or only warnings, add context
        if "evidence" not in finding or not finding["evidence"]:
            finding["evidence"] = ["No evidence captured"]
            return

        # If evidence is a list and contains only warnings, add note
        if isinstance(finding.get("evidence"), list):
            evidence_list = finding["evidence"]
            # Check if evidence contains only warnings/errors
            warning_indicators = ["warning", "undefined", "error", "fatal"]
            all_warnings = all(
                any(w in str(e).lower() for w in warning_indicators)
                for e in evidence_list
                if e
            )
            if all_warnings and len(evidence_list) < 3:
                # Add note that only warnings were captured
                finding["evidence"].append(
                    "[EVIDENCE] Only warning/error messages captured - full response may contain more data"
                )

        # Ensure response_length is captured
        if "response_length" not in finding:
            finding["response_length"] = 0

    # ==========================================================
    # MAIN SCANNER RUNNER - ALWAYS RETURNS LIST
    # ==========================================================

    def run_scanner(self, name: str, target: str) -> List:
        """
        Run a specific scanner.

        ALWAYS returns a list (never bool, None, or other types).
        """
        # Find the scanner
        scanner_config = None
        for s in self.scanners:
            if s["name"] == name:
                scanner_config = s
                break

        if not scanner_config:
            if not self.verbose:
                print(f"[ScanEngine] ❌ Scanner '{name}' not found")
            return []

        try:
            self._logger.info(f"Running scanner: {name}")
            scanner_class = scanner_config["class"]
            findings = []
            scanner_instance = None

            # ==========================================================
            # PATTERN 1: Scanner(target).scan() - SQLiScanner
            # ==========================================================
            try:
                scanner_instance = scanner_class(target)
                if hasattr(scanner_instance, "scan"):
                    import inspect

                    sig = inspect.signature(scanner_instance.scan)
                    params = list(sig.parameters.keys())

                    if "session" in params:
                        findings = scanner_instance.scan(session=self.session)
                    else:
                        findings = scanner_instance.scan()

                    if findings and isinstance(findings, list):
                        # Enrich findings with response data
                        for finding in findings:
                            if isinstance(finding, dict):
                                self._enrich_finding_with_response(finding)
                        self.findings.extend(findings)
                        self.statistics["findings_found"] += len(findings)
                        self.statistics["scanners_run"] += 1
                        return findings
            except TypeError:
                pass

            # ==========================================================
            # PATTERN 2: Scanner().scan(url) - SSRF, LFI, RFI
            # ==========================================================
            try:
                scanner_instance = scanner_class()
                if hasattr(scanner_instance, "scan"):
                    import inspect

                    sig = inspect.signature(scanner_instance.scan)
                    params = list(sig.parameters.keys())

                    if "url" in params:
                        findings = scanner_instance.scan(url=target)
                    elif "target" in params:
                        findings = scanner_instance.scan(target=target)
                    else:
                        findings = scanner_instance.scan()

                    if findings and isinstance(findings, list):
                        for finding in findings:
                            if isinstance(finding, dict):
                                self._enrich_finding_with_response(finding)
                        self.findings.extend(findings)
                        self.statistics["findings_found"] += len(findings)
                        self.statistics["scanners_run"] += 1
                        return findings
            except TypeError:
                pass

            # ==========================================================
            # PATTERN 3: Scanner(url, session).scan() - XSSScanner
            # ==========================================================
            try:
                if self.session:
                    scanner_instance = scanner_class(target, session=self.session)
                else:
                    scanner_instance = scanner_class(target)

                if hasattr(scanner_instance, "scan"):
                    import inspect

                    sig = inspect.signature(scanner_instance.scan)
                    params = list(sig.parameters.keys())

                    if "session" in params:
                        findings = scanner_instance.scan(session=self.session)
                    else:
                        findings = scanner_instance.scan()

                    if findings and isinstance(findings, list):
                        for finding in findings:
                            if isinstance(finding, dict):
                                self._enrich_finding_with_response(finding)
                        self.findings.extend(findings)
                        self.statistics["findings_found"] += len(findings)
                        self.statistics["scanners_run"] += 1
                        return findings
            except TypeError:
                pass

            # ==========================================================
            # PATTERN 4: Scanner().scan() - IDOR, CSRF, etc. (No args)
            # ==========================================================
            try:
                scanner_instance = scanner_class()
                if hasattr(scanner_instance, "scan"):
                    # Some scanners have target as attribute
                    if hasattr(scanner_instance, "target"):
                        scanner_instance.target = target
                    if hasattr(scanner_instance, "url"):
                        scanner_instance.url = target
                    if hasattr(scanner_instance, "set_target"):
                        scanner_instance.set_target(target)

                    findings = scanner_instance.scan()

                    if findings and isinstance(findings, list):
                        for finding in findings:
                            if isinstance(finding, dict):
                                self._enrich_finding_with_response(finding)
                        self.findings.extend(findings)
                        self.statistics["findings_found"] += len(findings)
                        self.statistics["scanners_run"] += 1
                        return findings
            except Exception:
                pass

            # ==========================================================
            # PATTERN 5: Scanner().run(target) - Some scanners use run()
            # ==========================================================
            try:
                scanner_instance = scanner_class()
                if hasattr(scanner_instance, "run"):
                    findings = scanner_instance.run(target)

                    if findings and isinstance(findings, list):
                        for finding in findings:
                            if isinstance(finding, dict):
                                self._enrich_finding_with_response(finding)
                        self.findings.extend(findings)
                        self.statistics["findings_found"] += len(findings)
                        self.statistics["scanners_run"] += 1
                        return findings
            except Exception:
                pass

            # ==========================================================
            # No findings - ALWAYS return empty list (never bool)
            # ==========================================================
            self._logger.debug(f"Scanner {name} found no findings")
            self.statistics["scanners_run"] += 1
            return []

        except Exception as e:
            self.statistics["errors"] += 1
            if not self.verbose:
                print(f"[ScanEngine] ❌ {name} failed: {e}")
            else:
                print(f"[VERBOSE] ❌ {name} failed: {e}")
                import traceback

                traceback.print_exc()
            self._logger.error(f"Scanner {name} failed: {e}")
            return []

    # ==========================================================
    # RUN SCANNERS - Clean output
    # ==========================================================

    def run_scanners(
        self, target: str, scanner_names: Optional[List[str]] = None
    ) -> List:
        """Run multiple scanners."""
        self.findings = []
        self.statistics["scanners_run"] = 0
        self.statistics["findings_found"] = 0
        self.statistics["errors"] = 0

        if scanner_names is None:
            scanner_names = [s["name"] for s in self.scanners]

        if not scanner_names:
            if not self.verbose:
                print("[ScanEngine] ⚠️ No scanners registered!")
            return []

        if not self.verbose:
            print("[ScanEngine] Running vulnerability scanners...")
        self._logger.info(f"Running {len(scanner_names)} scanners on {target}")

        for name in scanner_names:
            findings = self.run_scanner(name, target)
            if findings and isinstance(findings, list):
                self.findings.extend(findings)
                self.statistics["findings_found"] += len(findings)

        if not self.verbose:
            print(f"[ScanEngine] Scan complete: {len(self.findings)} findings found")
        self._logger.info(f"Scan complete: {len(self.findings)} findings found")
        return self.findings

    def run_all(self, target: str) -> List:
        """Run all registered scanners."""
        return self.run_scanners(target)

    def run(self, target: str, scanner_names: Optional[List[str]] = None) -> Dict:
        """Main run method for the scan engine."""
        findings = self.run_scanners(target, scanner_names)
        return {
            "findings": findings,
            "statistics": self.get_statistics(),
            "summary": self.get_summary(),
        }

    def get_findings(self) -> List:
        return self.findings

    def get_statistics(self) -> Dict:
        return self.statistics.copy()

    def get_summary(self) -> Dict:
        return {
            "total_scanners": self.statistics["total_scanners"],
            "scanners_run": self.statistics["scanners_run"],
            "findings_found": self.statistics["findings_found"],
            "errors": self.statistics["errors"],
        }

    def get_scanner_names(self) -> List[str]:
        return [s["name"] for s in self.scanners]

    def clear(self):
        self.findings = []
        self.statistics = {
            "total_scanners": len(self.scanners),
            "scanners_run": 0,
            "findings_found": 0,
            "errors": 0,
        }

    def close(self):
        if self.session:
            self.session.close()
        self._logger.info("Scan engine closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


ScannerEngine = ScanEngine


if __name__ == "__main__":
    engine = ScanEngine()
    print("=" * 60)
    print("SentinelAI Scan Engine Test")
    print("=" * 60)
    print(f"Registered scanners: {engine.get_scanner_names()}")
    print(f"Total scanners: {engine.statistics['total_scanners']}")
    print("=" * 60)
