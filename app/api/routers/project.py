"""
===========================================================
Project : Sentinel AI
Module  : Project API Router
File ID : API-PROJECT-001
Version : 2.0.0
===========================================================

Description:
Production REST API for Project Management.

===========================================================
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status

from sqlalchemy.orm import Session

from app.api.dependencies import (
    get_db,
    get_project_service,
)

from app.api.schemas.project import (
    ProjectCreate,
    ProjectUpdate,
    ProjectResponse,
    ProjectListResponse,
)

router = APIRouter(
    prefix="/projects",
    tags=["Projects"],
)


# ===========================================================
# Get All Projects
# ===========================================================


@router.get(
    "/",
    response_model=ProjectListResponse,
    status_code=status.HTTP_200_OK,
)
def get_projects(
    db: Session = Depends(get_db),
):

    service = get_project_service(
        db,
    )

    projects = service.list_projects()

    return ProjectListResponse(
        total=len(projects),
        projects=projects,
    )


# ===========================================================
# Get Project By ID
# ===========================================================


@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    status_code=status.HTTP_200_OK,
)
def get_project(
    project_id: str,
    db: Session = Depends(get_db),
):

    service = get_project_service(
        db,
    )

    project = service.get_project_by_id(
        project_id,
    )

    if project is None:

        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    return project


# ===========================================================
# Create Project
# ===========================================================


@router.post(
    "/",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_project(
    request: ProjectCreate,
    db: Session = Depends(get_db),
):

    service = get_project_service(
        db,
    )

    if service.project_exists(
        request.name,
    ):

        raise HTTPException(
            status_code=409,
            detail="Project already exists",
        )

    project = service.create_project(
        name=request.name,
        target=request.target,
        description=request.description,
    )

    return project


# ===========================================================
# Update Project
# ===========================================================


@router.put(
    "/{project_id}",
    response_model=ProjectResponse,
    status_code=status.HTTP_200_OK,
)
def update_project(
    project_id: str,
    request: ProjectUpdate,
    db: Session = Depends(get_db),
):

    service = get_project_service(
        db,
    )

    project = service.get_project_by_id(
        project_id,
    )

    if project is None:

        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    if request.name is not None:
        project.name = request.name

    if request.target is not None:
        project.target = request.target

    if request.description is not None:
        project.description = request.description

    if request.status is not None:
        project.status = request.status

    project = service.update_project(
        project,
    )

    return project


# ===========================================================
# Delete Project
# ===========================================================


@router.delete(
    "/{project_id}",
    status_code=status.HTTP_200_OK,
)
def delete_project(
    project_id: str,
    db: Session = Depends(get_db),
):

    service = get_project_service(
        db,
    )

    deleted = service.delete_project(
        project_id,
    )

    if not deleted:

        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    return {
        "success": True,
        "message": "Project deleted successfully",
    }


# ===========================================================
# Project Statistics
# ===========================================================


@router.get(
    "/{project_id}/statistics",
    status_code=status.HTTP_200_OK,
)
def project_statistics(
    project_id: str,
    db: Session = Depends(get_db),
):

    service = get_project_service(
        db,
    )

    project = service.get_project_by_id(
        project_id,
    )

    if project is None:

        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    return {
        "project_id": project.id,
        "name": project.name,
        "status": project.status,
        "target": project.target,
    }


# ===========================================================
# Project Health
# ===========================================================


@router.get(
    "/{project_id}/health",
    status_code=status.HTTP_200_OK,
)
def project_health(
    project_id: str,
    db: Session = Depends(get_db),
):

    service = get_project_service(
        db,
    )

    project = service.get_project_by_id(
        project_id,
    )

    if project is None:

        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    return {
        "status": "healthy",
        "database": "connected",
        "project": project.name,
    }


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":

    print("=" * 60)
    print("Project Router Loaded Successfully")
    print("=" * 60)

    print()

    print("Endpoints")

    print("GET     /projects")
    print("GET     /projects/{project_id}")
    print("POST    /projects")
    print("PUT     /projects/{project_id}")
    print("DELETE  /projects/{project_id}")
    print("GET     /projects/{project_id}/statistics")
    print("GET     /projects/{project_id}/health")
