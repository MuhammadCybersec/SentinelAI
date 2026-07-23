"""
===========================================================
Project : Sentinel AI
Module  : Finding Repository
File ID : DB-REPOSITORY-004
Version : 1.0.0
===========================================================

Description:
Repository responsible for CRUD operations on findings.
===========================================================
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.database.models.finding import Finding
from app.database.repositories.base_repository import BaseRepository


class FindingRepository(BaseRepository[Finding]):
    """
    Repository for Finding model.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:

        super().__init__(session)

        self.model = Finding

    # =====================================================
    # Create Finding
    # =====================================================

    def create_finding(
        self,
        finding: Finding,
    ) -> Finding:

        return self.create(finding)

    # =====================================================
    # Get Finding By ID
    # =====================================================

    def get_by_id(
        self,
        finding_id: str,
    ) -> Finding | None:

        return (
            self.session.query(self.model).filter(self.model.id == finding_id).first()
        )

    # =====================================================
    # Get Project Findings
    # =====================================================

    def get_project_findings(
        self,
        project_id: str,
    ) -> list[Finding]:

        return (
            self.session.query(self.model)
            .filter(self.model.project_id == project_id)
            .all()
        )

    # =====================================================
    # Get Findings By Severity
    # =====================================================

    def get_by_severity(
        self,
        project_id: str,
        severity: str,
    ) -> list[Finding]:

        return (
            self.session.query(self.model)
            .filter(
                self.model.project_id == project_id,
                self.model.severity == severity,
            )
            .all()
        )
        # =====================================================

    # Get Findings By Status
    # =====================================================

    def get_by_status(
        self,
        project_id: str,
        status: str,
    ) -> list[Finding]:

        return (
            self.session.query(self.model)
            .filter(
                self.model.project_id == project_id,
                self.model.status == status,
            )
            .all()
        )

    # =====================================================
    # Search Findings
    # =====================================================

    def search(
        self,
        project_id: str,
        keyword: str,
    ) -> list[Finding]:

        keyword = f"%{keyword}%"

        return (
            self.session.query(self.model)
            .filter(
                self.model.project_id == project_id,
                (
                    self.model.title.like(keyword)
                    | self.model.description.like(keyword)
                    | self.model.evidence.like(keyword)
                ),
            )
            .all()
        )

    # =====================================================
    # Update Finding Status
    # =====================================================

    def update_status(
        self,
        finding_id: str,
        status: str,
    ) -> Finding | None:

        finding = self.get_by_id(finding_id)

        if finding is None:
            return None

        finding.status = status

        self.session.commit()

        self.session.refresh(finding)

        return finding

    # =====================================================
    # Delete Finding
    # =====================================================

    def delete_finding(
        self,
        finding_id: str,
    ) -> bool:

        finding = self.get_by_id(finding_id)

        if finding is None:
            return False

        self.session.delete(finding)

        self.session.commit()

        return True

    # =====================================================
    # Count Findings
    # =====================================================

    def count_project_findings(
        self,
        project_id: str,
    ) -> int:

        return (
            self.session.query(self.model)
            .filter(
                self.model.project_id == project_id,
            )
            .count()
        )

    # =====================================================
    # Count By Severity
    # =====================================================

    def count_by_severity(
        self,
        project_id: str,
        severity: str,
    ) -> int:

        return (
            self.session.query(self.model)
            .filter(
                self.model.project_id == project_id,
                self.model.severity == severity,
            )
            .count()
        )
