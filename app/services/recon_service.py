"""
===========================================================
Project : Sentinel AI
Module  : Recon Service
File ID : SERVICE-RECON-001
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

from app.database.repositories.recon_result_repository import (
    ReconResultRepository,
)
from app.engines.recon_engine import ReconEngine
from app.modules.scanner.engine.scan_engine import ScanEngine
from app.services.finding_service import FindingService


class ReconService:
    """
    Service responsible for executing reconnaissance
    and storing results into the database.
    """

    def __init__(
        self,
        repository: ReconResultRepository,
        finding_service: FindingService,
    ) -> None:

        self.repository = repository
        self.engine = ReconEngine()
        self.scan_engine = ScanEngine(finding_service)

    # =====================================================
    # Run Recon
    # =====================================================

    def run(
        self,
        project_id: str,
        target: str,
    ) -> dict:

        results = self.engine.run(target)
        scan_results = self.scan_engine.run(
            project_id=project_id,
            target=target,
        )

        saved = 0

        for module_name, module_results in results.items():
            if module_name == "target":
                continue

            if not module_results:
                continue

            self.repository.save_results(
                project_id=project_id,
                module=module_name,
                results=module_results,
            )

            saved += 1

        return {
            "target": target,
            "modules": len(results),
            "saved": saved,
            "results": results,
            "scan": scan_results,
        }
