"""
===========================================================
Project : Sentinel AI
Module  : Scan Engine
File ID : SCANNER-ENGINE-001
Version : 1.0.0
===========================================================

Description:
Main vulnerability scanning engine.

Responsible for:

- Executing Recon
- Scope validation
- Running scanners
- Saving findings
- Producing scan statistics

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding
from app.modules.recon.engine.recon_engine import (
    ReconEngine,
)
from app.modules.recon.scope_manager import (
    ScopeManager,
)
from app.modules.scanner.modules.clickjacking import (
    ClickjackingScanner,
)
from app.modules.scanner.modules.cmd_injection import (
    CommandInjectionScanner,
)
from app.modules.scanner.modules.cors import (
    CORSScanner,
)
from app.modules.scanner.modules.crlf import (
    CRLFScanner,
)
from app.modules.scanner.modules.csrf import (
    CSRFScanner,
)
from app.modules.scanner.modules.file_upload import (
    FileUploadScanner,
)
from app.modules.scanner.modules.host_header import (
    HostHeaderScanner,
)
from app.modules.scanner.modules.idor import (
    IDORScanner,
)
from app.modules.scanner.modules.jwt import (
    JWTScanner,
)
from app.modules.scanner.modules.lfi import (
    LFIScanner,
)
from app.modules.scanner.modules.open_redirect import (
    OpenRedirectScanner,
)
from app.modules.scanner.modules.prototype_pollution import (
    PrototypePollutionScanner,
)
from app.modules.scanner.modules.rfi import (
    RFIScanner,
)
from app.modules.scanner.modules.sqli_v2 import SQLiV2Scanner as SQLiScanner
from app.modules.scanner.modules.ssrf import (
    SSRFScanner,
)

# ===========================================================
# Scanner Modules
# ===========================================================
from app.modules.scanner.modules.xss_v1 import (
    XSSScanner,
)
from app.services.finding_service import FindingService

# ===========================================================
# Scan Engine
# ===========================================================


class ScanEngine:
    """
    Sentinel AI Scan Engine.

    Responsibilities
    ----------------

    • Run reconnaissance

    • Validate scope

    • Execute all scanners

    • Save findings

    • Build statistics

    • Return final report
    """

    def __init__(
        self,
        finding_service: FindingService,
    ) -> None:

        self.finding_service = finding_service

        self.recon_engine = ReconEngine()

        self.scope_manager = ScopeManager()

        # ---------------------------------------------------
        # Scanner Registry
        # ---------------------------------------------------

        self.scanners = [
            XSSScanner(),
            SQLiScanner(
                target="",
                scope=self.scope_manager,
            ),
            SSRFScanner(),
            LFIScanner(),
            RFIScanner(),
            IDORScanner(),
            OpenRedirectScanner(),
            CommandInjectionScanner(),
            CRLFScanner(),
            CORSScanner(),
            CSRFScanner(),
            ClickjackingScanner(),
            FileUploadScanner(),
            JWTScanner(),
            HostHeaderScanner(),
            PrototypePollutionScanner(),
        ]

        # ---------------------------------------------------
        # Runtime Statistics
        # ---------------------------------------------------

        self.total_urls = 0

        self.scanned_urls = 0

        self.saved_findings = 0

        self.failed_scanners = 0

        self.scan_errors: list[str] = []

    # =======================================================
    # Public API
    # =======================================================

    # Run Scan
    # =======================================================

    def run(
        self,
        project_id: str,
        target: str,
    ) -> dict:
        """
        Execute complete scan workflow.
        """

        print("=" * 60)
        print("Sentinel AI Scanner")
        print("=" * 60)
        print()

        # ---------------------------------------------------
        # Reconnaissance
        # ---------------------------------------------------

        recon_result = self.recon_engine.run(
            target,
        )

        urls = recon_result.get(
            "urls",
            [],
        )

        # ---------------------------------------------------
        # Remove Duplicates
        # ---------------------------------------------------

        urls = sorted(
            set(urls),
        )

        # ---------------------------------------------------
        # Scope Filtering
        # ---------------------------------------------------

        scoped_urls: list[str] = []

        for url in urls:
            if self.scope_manager.is_allowed(
                url=url,
            ):
                scoped_urls.append(
                    url,
                )

        self.total_urls = len(
            scoped_urls,
        )

        print(f"Recon URLs      : {len(urls)}")

        print(f"In Scope URLs   : {self.total_urls}")

        print()

        # ---------------------------------------------------
        # Run Scanners
        # ---------------------------------------------------

        for index, url in enumerate(
            scoped_urls,
            start=1,
        ):
            print(f"[{index}/{self.total_urls}] {url}")

            self.scanned_urls += 1

            for scanner in self.scanners:
                try:
                    finding = self._run_scanner(
                        scanner=scanner,
                        project_id=project_id,
                        url=url,
                    )

                    if finding is not None:
                        self._save_finding(
                            finding,
                        )

                except (ValueError, RuntimeError) as exc:
                    self.failed_scanners += 1

                    self.scan_errors.append(f"{scanner.__class__.__name__}: {exc}")

                    print(f"ERROR -> {scanner.__class__.__name__}")

            print()

        # ---------------------------------------------------
        # Return Summary
        # ---------------------------------------------------

        return self._summary()
        # =======================================================

    # Execute Scanner
    # =======================================================

    def _run_scanner(
        self,
        scanner,
        project_id: str,
        url: str,
    ):

        print(f"   -> {scanner.__class__.__name__}")
        if scanner.__class__.__name__ == "SQLiScanner":
            scanner.target = url
            return scanner.scan()
        return scanner.scan(
            project_id=project_id,
            url=url,
        )

    # =======================================================
    # Save Finding
    # =======================================================

    def _save_finding(
        self,
        finding: Finding,
    ) -> None:
        """
        Store finding into database.
        """

        try:
            self.finding_service.create(
                finding,
            )

            self.saved_findings += 1

            print(f"      [+] {finding.title}")

        except Exception as exc:  # noqa: BLE001
            self.scan_errors.append(f"Save Finding Failed: {exc}")

            print("      [!] Failed to save finding")

    # =======================================================
    # Summary
    # =======================================================

    def _summary(
        self,
    ) -> dict:
        """
        Build scan summary.
        """

        return {
            "total_urls": self.total_urls,
            "scanned_urls": self.scanned_urls,
            "saved_findings": self.saved_findings,
            "failed_scanners": self.failed_scanners,
            "errors": self.scan_errors,
        }


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":
    from app.database.repositories.finding_repository import (
        FindingRepository,
    )
    from app.database.session import SessionLocal

    print("=" * 60)
    print("Sentinel AI Scanner Engine Test")
    print("=" * 60)
    print()

    db = SessionLocal()

    try:
        repository = FindingRepository(
            db,
        )

        service = FindingService(
            repository,
        )

        engine = ScanEngine(
            finding_service=service,
        )

        result = engine.run(
            project_id="demo-project",
            target="https://example.com",
        )

        print()

        print("=" * 60)
        print("Scan Summary")
        print("=" * 60)

        print(f"URLs Found          : {result['total_urls']}")

        print(f"URLs Scanned        : {result['scanned_urls']}")

        print(f"Findings Saved      : {result['saved_findings']}")

        print(f"Failed Scanners     : {result['failed_scanners']}")

        print(f"Errors              : {len(result['errors'])}")

        if result["errors"]:
            print()

            print("Error Log")

            for error in result["errors"]:
                print(f" - {error}")

    finally:
        db.close()
