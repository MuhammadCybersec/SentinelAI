"""
===========================================================
Project : Sentinel AI
Module  : Recon Result Repository
File ID : DB-REPOSITORY-003
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from app.database.models.recon_result import ReconResult
from app.database.repositories.base_repository import BaseRepository


class ReconResultRepository(BaseRepository[ReconResult]):
    """
    Repository for ReconResult model.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:

        super().__init__(session)

        self.model = ReconResult

    # =====================================================
    # Save Recon Results
    # =====================================================

    def save_results(
        self,
        project_id: str,
        module: str,
        results,
    ) -> None:
        """
        Save a complete module result into database.
        """

        if results is None:
            return

        if not isinstance(results, list):
            results = [results]

        records = []

        for item in results:

            records.append(
                ReconResult(
                    project_id=project_id,
                    module=module,
                    data=json.dumps(
                        item,
                        ensure_ascii=False,
                        default=str,
                    ),
                )
            )
        self.session.add_all(records)
        self.session.commit()

    # =====================================================
    # Get Project Results
    # =====================================================

    def get_project_results(
        self,
        project_id: str,
    ) -> list[ReconResult]:

        return (
            self.session.query(self.model)
            .filter(self.model.project_id == project_id)
            .all()
        )

    # =====================================================
    # Get Results By Module
    # =====================================================

    def get_module_results(
        self,
        project_id: str,
        module: str,
    ) -> list[ReconResult]:

        return (
            self.session.query(self.model)
            .filter(
                self.model.project_id == project_id,
                self.model.module == module,
            )
            .all()
        )

    # =====================================================
    # Delete Project Results
    # =====================================================

    def delete_project_results(
        self,
        project_id: str,
    ) -> None:

        (
            self.session.query(self.model)
            .filter(self.model.project_id == project_id)
            .delete()
        )

        self.session.commit()
