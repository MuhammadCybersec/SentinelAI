"""
===========================================================
Project : Sentinel AI
Module  : Findings API Router
File ID : API-FINDING-001
Version : 1.0.0
===========================================================

Description:
Production REST API for Findings.

===========================================================
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import (
    get_db,
    get_finding_manager,
)
from app.api.schemas.finding import (
    DeleteResponse,
    FindingCreate,
    FindingListResponse,
    FindingResponse,
    FindingStatisticsResponse,
    FindingStatusUpdate,
    FindingSummaryResponse,
)
from app.database.models.finding import Finding

router = APIRouter(
    prefix="/findings",
    tags=["Findings"],
)

# ===========================================================
# Get Finding
# ===========================================================


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
):

    manager = get_finding_manager(
        db,
    )

    finding = manager.get(
        finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    return finding


# ===========================================================
# Get Project Findings
# ===========================================================


@router.get(
    "/project/{project_id}",
    response_model=FindingListResponse,
)
def get_project_findings(
    project_id: str,
    db: Session = Depends(get_db),
):

    manager = get_finding_manager(
        db,
    )

    findings = manager.get_project_findings(
        project_id,
    )

    return FindingListResponse(
        total=len(findings),
        findings=[FindingResponse.model_validate(f) for f in findings],
    )


# ===========================================================
# Create Finding
# ===========================================================


@router.post(
    "/",
    response_model=FindingResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_finding(
    request: FindingCreate,
    db: Session = Depends(get_db),
):

    manager = get_finding_manager(
        db,
    )

    finding = Finding(
        project_id=request.project_id,
        title=request.title,
        description=request.description,
        severity=request.severity,
        cvss=request.cvss,
        status=request.status,
        module=request.module,
        target=request.target,
        url=request.url,
        parameter=request.parameter,
        payload=request.payload,
        evidence=request.evidence,
        recommendation=request.recommendation,
        reference=request.reference,
        cwe=request.cwe,
        owasp=request.owasp,
        cve=request.cve,
    )

    return manager.create(
        finding,
    )


# ===========================================================
# Update Finding Status
# ===========================================================


@router.patch(
    "/{finding_id}/status",
    response_model=FindingResponse,
)
def update_status(
    finding_id: str,
    request: FindingStatusUpdate,
    db: Session = Depends(get_db),
):

    manager = get_finding_manager(
        db,
    )

    finding = manager.update_status(
        finding_id,
        request.status,
    )

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    return finding


# ===========================================================
# Delete Finding
# ===========================================================


@router.delete(
    "/{finding_id}",
    response_model=DeleteResponse,
    status_code=status.HTTP_200_OK,
)
def delete_finding(
    finding_id: str,
    db: Session = Depends(get_db),
):

    manager = get_finding_manager(
        db,
    )

    deleted = manager.delete(
        finding_id,
    )

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    return DeleteResponse(
        success=True,
        message="Finding deleted successfully",
    )


# ===========================================================
# Search Findings
# ===========================================================


@router.get(
    "/project/{project_id}/search",
    response_model=FindingListResponse,
)
def search_findings(
    project_id: str,
    keyword: str = Query(
        ...,
        min_length=1,
    ),
    db: Session = Depends(get_db),
):

    manager = get_finding_manager(
        db,
    )

    findings = manager.search(
        project_id,
        keyword,
    )

    return FindingListResponse(
        total=len(findings),
        findings=[FindingResponse.model_validate(f) for f in findings],
    )


# ===========================================================
# Findings By Severity
# ===========================================================


@router.get(
    "/project/{project_id}/severity/{severity}",
    response_model=FindingListResponse,
)
def findings_by_severity(
    project_id: str,
    severity: str,
    db: Session = Depends(get_db),
):

    manager = get_finding_manager(
        db,
    )

    findings = manager.get_by_severity(
        project_id,
        severity,
    )

    return FindingListResponse(
        total=len(findings),
        findings=[FindingResponse.model_validate(f) for f in findings],
    )


# ===========================================================
# Findings By Status
# ===========================================================


@router.get(
    "/project/{project_id}/status/{finding_status}",
    response_model=FindingListResponse,
)
def findings_by_status(
    project_id: str,
    finding_status: str,
    db: Session = Depends(get_db),
):

    manager = get_finding_manager(
        db,
    )

    findings = manager.get_by_status(
        project_id,
        finding_status,
    )

    return FindingListResponse(
        total=len(findings),
        findings=[FindingResponse.model_validate(f) for f in findings],
    )


# ===========================================================
# Finding Statistics
# ===========================================================


@router.get(
    "/project/{project_id}/statistics",
    response_model=FindingStatisticsResponse,
)
def finding_statistics(
    project_id: str,
    db: Session = Depends(get_db),
):

    manager = get_finding_manager(
        db,
    )

    stats = manager.statistics(
        project_id,
    )

    return FindingStatisticsResponse(
        **stats,
    )


# ===========================================================
# Finding Summary
# ===========================================================


@router.get(
    "/project/{project_id}/summary",
    response_model=FindingSummaryResponse,
)
def finding_summary(
    project_id: str,
    db: Session = Depends(get_db),
):

    manager = get_finding_manager(
        db,
    )

    summary = manager.summary(
        project_id,
    )

    return FindingSummaryResponse(
        **summary,
    )


# ===========================================================
# Health
# ===========================================================


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
)
def health():

    return {
        "status": "healthy",
        "service": "Findings API",
    }


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Findings Router Loaded Successfully")
    print("=" * 60)

    print()

    print("Available Endpoints")

    print("GET     /findings/{finding_id}")
    print("GET     /findings/project/{project_id}")
    print("POST    /findings/")
    print("PATCH   /findings/{finding_id}/status")
    print("DELETE  /findings/{finding_id}")
    print("GET     /findings/project/{project_id}/search")
    print("GET     /findings/project/{project_id}/severity/{severity}")
    print("GET     /findings/project/{project_id}/status/{finding_status}")
    print("GET     /findings/project/{project_id}/statistics")
    print("GET     /findings/project/{project_id}/summary")
    print("GET     /findings/health")
