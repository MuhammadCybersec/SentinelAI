"""
===========================================================
Project : Sentinel AI
Module  : Finding Service
File ID : SERVICE-FINDING-001
Version : 1.0.0
===========================================================

Description:
Business logic layer for vulnerability findings.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding
from app.database.repositories.finding_repository import (
    FindingRepository,
)


class FindingService:
    """
    Service responsible for managing findings.
    """

    def __init__(
        self,
        repository: FindingRepository,
    ) -> None:

        self.repository = repository

    # =====================================================
    # Create Finding
    # =====================================================

    def create(
        self,
        finding: Finding,
    ) -> Finding:

        return self.repository.create_finding(
            finding,
        )

    # =====================================================
    # Get Finding
    # =====================================================

    def get(
        self,
        finding_id: str,
    ) -> Finding | None:

        return self.repository.get_by_id(
            finding_id,
        )

    # =====================================================
    # Get Project Findings
    # =====================================================

    def get_project_findings(
        self,
        project_id: str,
    ) -> list[Finding]:

        return self.repository.get_project_findings(
            project_id,
        )

    # =====================================================
    # Get Findings By Severity
    # =====================================================

    def get_by_severity(
        self,
        project_id: str,
        severity: str,
    ) -> list[Finding]:

        return self.repository.get_by_severity(
            project_id,
            severity,
        )

    # =====================================================
    # Get Findings By Status
    # =====================================================

    def get_by_status(
        self,
        project_id: str,
        status: str,
    ) -> list[Finding]:

        return self.repository.get_by_status(
            project_id,
            status,
        )
        # =====================================================

    # Search Findings
    # =====================================================

    def search(
        self,
        project_id: str,
        keyword: str,
    ) -> list[Finding]:

        return self.repository.search(
            project_id,
            keyword,
        )

    # =====================================================
    # Update Status
    # =====================================================

    def update_status(
        self,
        finding_id: str,
        status: str,
    ) -> Finding | None:

        return self.repository.update_status(
            finding_id,
            status,
        )

    # =====================================================
    # Delete Finding
    # =====================================================

    def delete(
        self,
        finding_id: str,
    ) -> bool:

        return self.repository.delete_finding(
            finding_id,
        )

    # =====================================================
    # Statistics
    # =====================================================

    def statistics(
        self,
        project_id: str,
    ) -> dict:

        return {
            "total": self.repository.count_project_findings(
                project_id,
            ),
            "critical": self.repository.count_by_severity(
                project_id,
                "Critical",
            ),
            "high": self.repository.count_by_severity(
                project_id,
                "High",
            ),
            "medium": self.repository.count_by_severity(
                project_id,
                "Medium",
            ),
            "low": self.repository.count_by_severity(
                project_id,
                "Low",
            ),
            "info": self.repository.count_by_severity(
                project_id,
                "Info",
            ),
        }

    # =====================================================
    # Project Summary
    # =====================================================

    def summary(
        self,
        project_id: str,
    ) -> dict:

        findings = self.get_project_findings(
            project_id,
        )

        stats = self.statistics(
            project_id,
        )

        return {
            "project_id": project_id,
            "total_findings": len(findings),
            "statistics": stats,
            "findings": findings,
        }
