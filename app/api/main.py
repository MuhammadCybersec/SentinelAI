"""
===========================================================
Project : Sentinel AI
Module  : FastAPI Main Application
File ID : API-MAIN-001
Version : 1.0.0
===========================================================

Description:
Sentinel AI REST API entry point.

===========================================================
"""

from __future__ import annotations

from fastapi import FastAPI

from app.api.routers.project import router as project_router


from app.api.routers.findings import (
    router as findings_router,
)

# ===========================================================
# Create FastAPI Application
# ===========================================================

app = FastAPI(
    title="Sentinel AI API",
    description=("Enterprise AI-Powered " "Vulnerability Assessment Platform"),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ===========================================================
# Routers
# ===========================================================

app.include_router(
    project_router,
)

app.include_router(
    findings_router,
)
# ===========================================================
# Root Endpoint
# ===========================================================


@app.get(
    "/",
    tags=["Root"],
)
def root():

    return {
        "application": "Sentinel AI",
        "version": "1.0.0",
        "status": "running",
        "message": "Welcome to Sentinel AI API",
    }


# ===========================================================
# Health Check
# ===========================================================


@app.get(
    "/health",
    tags=["Health"],
)
def health():

    return {
        "status": "healthy",
        "service": "Sentinel AI",
    }


# ===========================================================
# API Information
# ===========================================================


@app.get(
    "/info",
    tags=["System"],
)
def info():

    return {
        "name": "Sentinel AI",
        "version": "1.0.0",
        "author": "Sentinel AI Team",
        "api_version": "v1",
        "documentation": "/docs",
        "redoc": "/redoc",
        "openapi": "/openapi.json",
    }


# ===========================================================
# Startup Event
# ===========================================================


@app.on_event("startup")
async def startup_event():

    print("=" * 60)
    print("Starting Sentinel AI API...")
    print("=" * 60)

    print("API Started Successfully")


# ===========================================================
# Shutdown Event
# ===========================================================


@app.on_event("shutdown")
async def shutdown_event():

    print("=" * 60)
    print("Stopping Sentinel AI API...")
    print("=" * 60)

    print("API Shutdown Complete")


# ===========================================================
# Run Server
# ===========================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "app.api.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
