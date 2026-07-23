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


class ReconService:
    """
    Service responsible for executing reconnaissance
    and storing results into the database.
    """

    def __init__(
        self,
        repository: ReconResultRepository,
    ) -> None:

        self.repository = repository
        self.engine = ReconEngine()

    # =====================================================
    # Run Recon
    # =====================================================

    def run(
        self,
        project_id: str,
        target: str,
    ) -> dict:

        results = self.engine.run(target)

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
        }
