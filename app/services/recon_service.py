"""
Recon Service - Complete Fixed Version
"""

import json
import logging
import re
import traceback
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.database.repositories.finding_repository import FindingRepository
from app.database.repositories.recon_result_repository import ReconResultRepository
from app.modules.browser.login_manager import dvwa_login
from app.modules.recon.engine.recon_engine import ReconEngine
from app.modules.scanner.engine.scan_engine import ScanEngine

logger = logging.getLogger(__name__)


class ReconService:
    """Reconnaissance and Scanning Service."""

    def __init__(
        self,
        recon_repo: ReconResultRepository,
        finding_repo: FindingRepository,
    ):
        self.recon_repo = recon_repo
        self.finding_repo = finding_repo
        self.session = None
        self.engine = ReconEngine()
        self.scan_engine = ScanEngine(verbose=False)

        self.url_scanner_map = {
            "vulnerabilities/sqli": ["sqli"],
            "vulnerabilities/sqli_blind": ["sqli"],
            "vulnerabilities/xss_d": ["xss"],
            "vulnerabilities/xss_r": ["xss"],
            "vulnerabilities/xss_s": ["xss"],
            "vulnerabilities/fi": ["lfi", "rfi"],
            "vulnerabilities/exec": ["cmd_injection"],
            "vulnerabilities/csrf": ["csrf"],
            "vulnerabilities/upload": ["file_upload"],
            "vulnerabilities/open_redirect": ["open_redirect"],
            "vulnerabilities/weak_id": ["idor"],
        }

        self._run_scanners = set()
        self._normalized_target = None

    # ==========================================================
    # URL CANONICALIZATION - FIXED
    # ==========================================================

    def _canonicalize_url(self, url: str) -> str:
        """
        Convert URL to canonical form - remove markdown.

        FIX: Always returns plain URL, never markdown.
        """
        if not url:
            return url

        url = url.strip()

        # Remove markdown link format: [text](url)
        markdown_match = re.search(r"\[.*?\]\((.*?)\)", url)
        if markdown_match:
            url = markdown_match.group(1)

        # Remove brackets, parentheses, extra characters
        url = url.replace("[", "").replace("]", "").replace("(", "").replace(")", "")
        url = url.strip()

        # Handle multiple markdown patterns
        if "](" in url:
            markdown_match = re.search(r"\[.*?\]\((.*?)\)", url)
            if markdown_match:
                url = markdown_match.group(1)

        # Validate and return
        try:
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                return url
        except Exception:
            pass

        return url

    def normalize_target_url(self, target: str) -> str:
        """Public method to normalize target URL."""
        return self._canonicalize_url(target)

    # ==========================================================
    # DVWA Login
    # ==========================================================

    def _login_dvwa(self, target: str) -> Optional[Dict]:
        """Login to DVWA."""
        print("=" * 60)
        print("DVWA Login")
        print("=" * 60)

        session = dvwa_login(target, username="admin", password="password")

        if session:
            print("=" * 60)
            return {
                "session": session,
                "security_level": "low",
            }
        else:
            print("[WARNING] Login failed, scanning may be limited")
            print("=" * 60)
            return None

    # ==========================================================
    # Evidence Normalization
    # ==========================================================

    def _normalize_evidence(self, evidence: Any) -> List[str]:
        """Normalize evidence to a list of strings."""
        if evidence is None:
            return []
        if isinstance(evidence, bool):
            return ["True"] if evidence else ["False"]
        if isinstance(evidence, str):
            return [evidence] if evidence.strip() else []
        if isinstance(evidence, (list, tuple)):
            result = []
            for item in evidence:
                if item is None:
                    continue
                if isinstance(item, bool):
                    result.append("True" if item else "False")
                else:
                    result.append(str(item))
            return result
        if isinstance(evidence, dict):
            return [json.dumps(evidence)]
        return [str(evidence)]

    def _normalize_finding(self, finding: Dict) -> Dict:
        """Normalize a finding."""
        evidence = finding.get("evidence")
        finding["evidence"] = self._normalize_evidence(evidence)

        references = finding.get("references")
        if references is None:
            finding["references"] = []
        elif isinstance(references, bool):
            finding["references"] = []
        elif isinstance(references, str):
            finding["references"] = [references]
        elif isinstance(references, list):
            finding["references"] = [str(r) for r in references if r is not None]

        if "vulnerability_type" not in finding and "type" in finding:
            finding["vulnerability_type"] = finding["type"]

        # FIX: Canonicalize URLs
        if "url" in finding:
            finding["url"] = self._canonicalize_url(finding["url"])
        if "target" in finding:
            finding["target"] = self._canonicalize_url(finding["target"])

        return finding

    # ==========================================================
    # OS Detection
    # ==========================================================

    def _detect_os(self, evidence_text: str, payload: str) -> str:
        """Detect target OS from evidence and payload."""
        windows_indicators = [
            "windows",
            "win.ini",
            "boot.ini",
            "system32",
            "xampp",
            "apache",
        ]
        if any(indicator in evidence_text for indicator in windows_indicators):
            return "windows"
        if "win.ini" in payload or "boot.ini" in payload or "autoexec.bat" in payload:
            return "windows"

        linux_indicators = ["/etc/passwd", "/etc/hosts", "/proc/", "shadow", "root:"]
        if any(indicator in evidence_text for indicator in linux_indicators):
            return "linux"
        if "etc/passwd" in payload or "etc/hosts" in payload:
            return "linux"

        return "unknown"

    def _is_os_compatible_payload(self, payload: str, os_type: str) -> bool:
        """Check if payload is compatible with the target OS."""
        if os_type == "windows":
            linux_patterns = [
                "/etc/",
                "/proc/",
                "/var/",
                "/usr/",
                "/bin/",
                "/lib/",
                "etc/passwd",
                "etc/hosts",
                "etc/shadow",
                "proc/self",
            ]
            for pattern in linux_patterns:
                if pattern in payload:
                    return False
            return True
        elif os_type == "linux":
            windows_patterns = [
                "win.ini",
                "boot.ini",
                "autoexec.bat",
                "system32",
                "windows",
                "Program Files",
                "xampp",
            ]
            for pattern in windows_patterns:
                if pattern in payload.lower():
                    return False
            return True
        return True

    def _get_requested_file(self, payload: str) -> str:
        """Extract the requested file from payload."""
        clean_payload = re.sub(r"\.\./|\.\.\\", "", payload)
        clean_payload = clean_payload.split("?")[0].split("#")[0]
        return clean_payload.strip()

    def _is_php_filter_payload(self, payload: str) -> bool:
        """Check if payload is a PHP filter wrapper."""
        return (
            "php://filter" in payload
            or "php://input" in payload
            or "php://output" in payload
        )

    # ==========================================================
    # LFI File Fingerprints - High Specificity
    # ==========================================================

    def _get_lfi_file_fingerprints(self, filename: str) -> Dict[str, Any]:
        """
        Get LFI file fingerprints for verification.

        FIX: High-specificity fingerprints only.
        """
        fingerprints = {
            "win.ini": {
                "content": [
                    "[fonts]",
                    "[extensions]",
                    "[mail]",
                    "[mci]",
                    "mci extensions",
                    "for 16-bit app support",
                ],
                "min_matches": 2,
                "confidence": 85,
                "specificity": "HIGH",
            },
            "boot.ini": {
                "content": [
                    "[boot loader]",
                    "timeout=",
                    "default=",
                    "[operating systems]",
                    "multi(",
                    "disk(",
                ],
                "min_matches": 2,
                "confidence": 90,
                "specificity": "HIGH",
            },
            "autoexec.bat": {
                "content": ["@echo off", "set path=", "prompt"],
                "min_matches": 2,
                "confidence": 60,
                "specificity": "HIGH",
            },
            "hosts": {
                "content": ["127.0.0.1 localhost", "::1 localhost"],
                "min_matches": 2,
                "confidence": 95,
                "specificity": "HIGH",
            },
            "passwd": {
                "content": ["root:x:0:0", "daemon:x:1:1", "bin:x:2:2", "sys:x:3:3"],
                "min_matches": 2,
                "confidence": 95,
                "specificity": "HIGH",
            },
            "shadow": {
                "content": ["root:", "daemon:", "bin:", "sys:"],
                "min_matches": 2,
                "confidence": 90,
                "specificity": "HIGH",
            },
        }

        for key in fingerprints:
            if key in filename.lower():
                return fingerprints[key]

        return {"content": [], "min_matches": 0, "confidence": 10, "specificity": "LOW"}

    # ==========================================================
    # RFI Helper Functions
    # ==========================================================

    def _has_rfi_canary(self, evidence_text: str) -> bool:
        """Check if RFI canary/unique marker is present."""
        canary_patterns = [
            "SENTINELAI_RFI_CANARY",
            "RFI_TEST_CANARY",
            "REMOTE_FILE_CONTENT",
            "TEST_CANARY_7F3A91",
            "rfi_test",
            "test_content",
            "remote_file",
        ]

        for pattern in canary_patterns:
            if pattern.lower() in evidence_text:
                return True

        return False

    def _has_rfi_remote_content(
        self, evidence_text: str, payload: str
    ) -> Tuple[bool, List[str]]:
        """
        Check if RFI remote content appears in response.

        Returns:
            Tuple of (has_content, matched_indicators)
        """
        matched = []

        # Check if remote URL appears in response
        if "http://" in evidence_text or "https://" in evidence_text:
            matched.append("remote_url_in_response")

        # Check for remote content patterns
        remote_indicators = {
            "test": "test_content",
            "remote": "remote_content",
            "external": "external_content",
            "included": "included_content",
            "shell": "shell_content",
            "txt": "txt_content",
            "content": "content_text",
        }

        for indicator, label in remote_indicators.items():
            if indicator in evidence_text:
                # Make sure it's not just the payload URL being reflected
                if indicator not in payload.lower():
                    matched.append(label)

        return len(matched) > 0, matched

    def _get_rfi_canary_from_finding(self, finding: Dict) -> Tuple[bool, Optional[str]]:
        """Extract canary information from finding."""
        canary_found = finding.get("canary_found", False)
        canary_value = finding.get("canary", None)
        return canary_found, canary_value

    # ==========================================================
    # VERIFICATION - FIXED RFI and LFI
    # ==========================================================

    def _verify_finding(self, finding: Dict) -> Dict:
        """
        Verify finding with vulnerability-specific evidence.

        FIX: RFI requires canary or strong remote content evidence.
        """
        vulnerability_type = finding.get(
            "type", finding.get("vulnerability_type", "Unknown")
        )
        evidence_list = self._normalize_evidence(finding.get("evidence", []))
        evidence_text = " ".join(evidence_list).lower()
        payload = finding.get("payload", "")
        status_code = finding.get("status_code", 0)
        response_length = finding.get("response_length", 0)

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"Verifying: type={vulnerability_type}, scanner={finding.get('scanner_name')}"
            )

        # Step 1: Detect OS
        detected_os = self._detect_os(evidence_text, payload)

        # Step 2: Check OS compatibility
        if not self._is_os_compatible_payload(payload, detected_os):
            finding["verified"] = False
            finding["confidence"] = 0.0
            finding["severity"] = "Info"
            finding["verification_reason"] = "not_applicable_os_incompatible"
            finding["verification_status"] = "NOT_APPLICABLE"
            return finding

        # Step 3: Get requested file and fingerprints
        requested_file = self._get_requested_file(payload)

        fingerprints = self._get_lfi_file_fingerprints(requested_file)
        content_indicators = fingerprints.get("content", [])
        min_matches = fingerprints.get("min_matches", 2)
        base_confidence = fingerprints.get("confidence", 10)
        specificity = fingerprints.get("specificity", "LOW")

        # Step 4: Check for matched indicators - EXACT matches
        matched_indicators = []
        for indicator in content_indicators:
            if indicator.lower() in evidence_text:
                matched_indicators.append(indicator)

        # Step 5: Decision logic
        verified = False
        verification_reason = ""
        verification_status = "REJECTED"
        confidence = 10.0
        confidence_reasons = []
        evidence_strength = "NONE"

        # ==========================================================
        # LFI Verification - EVIDENCE-BASED
        # ==========================================================
        if vulnerability_type == "LFI":
            if self._is_php_filter_payload(payload):
                has_base64 = any(
                    re.match(r"^[A-Za-z0-9+/=]+$", ev.strip()) for ev in evidence_list
                )
                if has_base64:
                    verified = True
                    verification_reason = "base64_content_decoded"
                    verification_status = "VERIFIED"
                    confidence = 70.0
                    confidence_reasons = ["base64_content_detected"]
                    evidence_strength = "STRONG"
                else:
                    verification_status = "INCONCLUSIVE"
                    verification_reason = "php_filter_attempted_no_base64"
                    confidence = 30.0
                    confidence_reasons = ["php_filter_attempted"]
                    evidence_strength = "WEAK"
            else:
                match_count = len(matched_indicators)

                # HIGH specificity: require all matches
                if specificity == "HIGH" and match_count >= min_matches:
                    verified = True
                    verification_reason = f"file_content_verified_{requested_file}"
                    verification_status = "VERIFIED"
                    confidence = base_confidence
                    confidence_reasons = [f"matched_{match_count}_specific_indicators"]
                    evidence_strength = "STRONG"
                elif match_count >= 1 and specificity == "HIGH":
                    # HIGH specificity but partial match
                    verification_status = "INCONCLUSIVE"
                    verification_reason = f"partial_match_{requested_file}"
                    confidence = min(30.0, 15 + (match_count * 10))
                    confidence_reasons = [f"partial_match_{match_count}_indicators"]
                    evidence_strength = "WEAK"
                elif response_length > 100 and ("/" in payload or "\\" in payload):
                    # Payload attempted but no content match
                    verification_status = "INCONCLUSIVE"
                    verification_reason = "payload_attempted_no_content"
                    confidence = 15.0
                    confidence_reasons = ["path_traversal_attempted"]
                    evidence_strength = "WEAK"
                else:
                    verification_status = "REJECTED"
                    verification_reason = "no_content_indicators"
                    confidence = 5.0
                    confidence_reasons = ["no_evidence"]
                    evidence_strength = "NONE"

        # ==========================================================
        # RFI Verification - FIXED: Requires canary or strong proof
        # ==========================================================
        elif vulnerability_type == "RFI":
            # Check if finding has canary information from scanner
            canary_found, canary_value = self._get_rfi_canary_from_finding(finding)

            # Check for remote content indicators
            has_remote_content, remote_matches = self._has_rfi_remote_content(
                evidence_text, payload
            )

            # Check for include warnings
            include_warning = (
                "warning: include" in evidence_text
                or "warning: require" in evidence_text
            ) or ("failed to open stream" in evidence_text)

            # Check for remote URL in response
            remote_url_in_response = (
                "http://" in evidence_text or "https://" in evidence_text
            )

            # Check for PHP code indicators
            php_indicators = ["<?php", "echo", "print", "function", "class"]
            has_php_indicators = any(kw in evidence_text for kw in php_indicators)

            # ==========================================================
            # DECISION LOGIC - STRICT EVIDENCE-BASED
            # ==========================================================

            # Level 1: STRONG - Canary found (controlled remote content included)
            if canary_found:
                verified = True
                verification_reason = f"rfi_canary_detected_{canary_value or 'unknown'}"
                verification_status = "VERIFIED"
                confidence = 85.0
                confidence_reasons = ["canary_detected", "remote_content_included"]
                evidence_strength = "STRONG"
                logger.debug(f"RFI → VERIFIED: Canary detected: {canary_value}")

            # Level 2: STRONG - Remote code execution detected
            elif has_remote_content and has_php_indicators and include_warning:
                verified = True
                verification_reason = "remote_code_execution_detected"
                verification_status = "VERIFIED"
                confidence = 75.0
                confidence_reasons = [
                    "remote_code_execution",
                    "remote_content_detected",
                ]
                evidence_strength = "STRONG"
                logger.debug(f"RFI → VERIFIED: Remote code execution detected")

            # Level 3: MEDIUM - Remote content included but no canary
            elif has_remote_content and remote_url_in_response:
                verification_status = "INCONCLUSIVE"
                verification_reason = "remote_content_detected_no_canary"
                confidence = 45.0
                confidence_reasons = [
                    "remote_content_detected",
                    "remote_url_in_response",
                ]
                evidence_strength = "MEDIUM"
                logger.debug(f"RFI → INCONCLUSIVE: Remote content detected, no canary")

            # Level 4: WEAK - Remote URL reflected only
            elif remote_url_in_response:
                verification_status = "INCONCLUSIVE"
                verification_reason = "remote_url_reflected_only"
                confidence = 25.0
                confidence_reasons = ["remote_url_in_response"]
                evidence_strength = "WEAK"
                logger.debug(f"RFI → INCONCLUSIVE: Remote URL reflected only")

            # Level 5: WEAK - Remote payload sent but no evidence
            elif "http://" in payload:
                verification_status = "INCONCLUSIVE"
                verification_reason = "remote_payload_sent_no_evidence"
                confidence = 15.0
                confidence_reasons = ["remote_payload_sent"]
                evidence_strength = "WEAK"
                logger.debug(f"RFI → INCONCLUSIVE: Remote payload sent, no evidence")

            # Level 6: REJECTED - No evidence
            else:
                verification_status = "REJECTED"
                verification_reason = "no_rfi_evidence"
                confidence = 5.0
                confidence_reasons = ["no_evidence"]
                evidence_strength = "NONE"
                logger.debug(f"RFI → REJECTED: No RFI evidence")

        # ==========================================================
        # SQL Injection Verification
        # ==========================================================
        elif vulnerability_type == "SQL Injection":
            if any(
                kw in evidence_text
                for kw in ["mysql_fetch", "sql syntax", "mysqli_error"]
            ):
                verified = True
                verification_reason = "sql_error_detected"
                verification_status = "VERIFIED"
                confidence = 70.0
                confidence_reasons = ["sql_error"]
                evidence_strength = "STRONG"
            else:
                verification_status = "INCONCLUSIVE"
                verification_reason = "no_sql_error"
                confidence = 20.0
                confidence_reasons = ["no_sql_error"]
                evidence_strength = "WEAK"

        # ==========================================================
        # XSS Verification
        # ==========================================================
        elif vulnerability_type == "XSS":
            if any(kw in evidence_text for kw in ["<script", "alert(", "onerror"]):
                verified = True
                verification_reason = "script_execution_detected"
                verification_status = "VERIFIED"
                confidence = 70.0
                confidence_reasons = ["script_detected"]
                evidence_strength = "STRONG"
            else:
                verification_status = "INCONCLUSIVE"
                verification_reason = "no_script_execution"
                confidence = 20.0
                confidence_reasons = ["no_script_execution"]
                evidence_strength = "WEAK"

        # ==========================================================
        # Final decision
        # ==========================================================
        confidence = min(confidence, 100.0)

        finding["confidence"] = round(confidence, 1)
        finding["verified"] = verified
        finding["is_false_positive"] = False
        finding["verification_reason"] = verification_reason
        finding["verification_status"] = verification_status
        finding["matched_indicators"] = matched_indicators
        finding["confidence_reasons"] = confidence_reasons
        finding["evidence_strength"] = evidence_strength
        finding["specificity"] = specificity

        # Set severity based on status
        if verification_status == "VERIFIED":
            if confidence >= 80:
                finding["severity"] = "Critical"
            elif confidence >= 60:
                finding["severity"] = "High"
            elif confidence >= 40:
                finding["severity"] = "Medium"
            else:
                finding["severity"] = "Low"
        elif verification_status == "INCONCLUSIVE":
            finding["severity"] = "Info"
        else:
            finding["severity"] = "Info"

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"→ status={verification_status}, verified={verified}, confidence={confidence}"
            )

        return finding

    # ==========================================================
    # DATABASE SAVE
    # ==========================================================

    def _save_finding_to_database(self, project_id: str, finding: Dict) -> bool:
        """Save a single finding to database."""
        verification_status = finding.get("verification_status", "REJECTED")

        # Only save VERIFIED or INCONCLUSIVE
        if verification_status not in ["VERIFIED", "INCONCLUSIVE"]:
            return False

        confidence = finding.get("confidence", 0.0)

        if verification_status == "INCONCLUSIVE":
            finding["verified"] = False
            if confidence > 50:
                confidence = 40.0
            finding["confidence"] = confidence
            finding["severity"] = "Info"

        try:
            from app.database.session import SessionLocal
            from app.database.models.finding import Finding
            from app.database.models.project import Project

            db = SessionLocal()
            try:
                project = db.query(Project).filter(Project.id == project_id).first()
                if not project:
                    logger.error(f"Project {project_id} not found")
                    return False

                evidence_list = self._normalize_evidence(finding.get("evidence", []))
                evidence_str = "\n".join(evidence_list) if evidence_list else ""

                clean_url = self._canonicalize_url(finding.get("url", ""))

                title = finding.get(
                    "title", f"{finding.get('type', 'Unknown')} Vulnerability"
                )
                if verification_status == "INCONCLUSIVE":
                    title = f"[CANDIDATE] {title}"

                db_finding = Finding(
                    id=str(uuid.uuid4()),
                    project_id=project_id,
                    title=title,
                    description=finding.get("description", ""),
                    severity=finding.get("severity", "Medium"),
                    cvss=(
                        7.5 if finding.get("severity") in ["Critical", "High"] else 5.0
                    ),
                    status=(
                        "Open"
                        if verification_status == "VERIFIED"
                        else "Pending Review"
                    ),
                    module=finding.get("scanner_name", "unknown"),
                    target=clean_url,
                    scanner_name=finding.get("scanner_name", "unknown"),
                    url=clean_url,
                    method=finding.get("method", "GET"),
                    parameter=finding.get("parameter", ""),
                    payload=finding.get("payload", ""),
                    status_code=finding.get("status_code", 0),
                    response_time=finding.get("response_time", 0.0),
                    evidence=evidence_str,
                    recommendation=finding.get(
                        "recommendation", "Review and fix the vulnerability"
                    ),
                    confidence=confidence,
                    is_false_positive=finding.get("is_false_positive", False),
                    verified=finding.get("verified", False),
                    cwe=finding.get("cwe", ""),
                    owasp=finding.get("owasp", ""),
                    discovered_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                )

                db.add(db_finding)
                db.commit()
                logger.info(f"✅ Finding saved: {db_finding.id}")
                return True

            except Exception as e:
                db.rollback()
                logger.error(f"Database error: {e}")
                return False
            finally:
                db.close()

        except Exception as e:
            logger.error(f"Failed to save finding: {e}")
            return False

    # ==========================================================
    # RUN
    # ==========================================================

    def run(self, project_id: str, target: str) -> Dict:
        """Execute full recon and scanning workflow."""
        # FIX: Canonicalize target URL at start
        target = self._canonicalize_url(target)
        self._normalized_target = target

        logger.info(f"Starting Recon: {target}")

        # Authentication
        login_result = None
        if "localhost/DVWA" in target or "DVWA" in target:
            login_result = self._login_dvwa(target)
            if login_result:
                self.session = login_result.get("session")
                self.scan_engine.session = self.session

        # Recon
        print("[Recon] Discovering URLs...")
        recon_result = self.engine.run(target)
        urls = recon_result.get("urls", [])
        print(f"[Recon] URLs discovered: {len(urls)}")

        print("\n" + "=" * 60)
        print("Recon Summary")
        print("=" * 60)
        print(f"URLs discovered   : {len(urls)}")
        print(f"Interesting URLs  : {len(recon_result.get('interesting_urls', []))}")
        print(f"Parameters found  : {len(recon_result.get('parameters', {}))}")
        print(f"Forms discovered  : {len(recon_result.get('forms', []))}")
        print(
            f"Technology        : {recon_result.get('technologies', {}).get('Server', 'Unknown')}"
        )
        print(
            f"WAF Detected      : {recon_result.get('waf', {}).get('detected', False)}"
        )
        print("=" * 60)

        # Scan
        all_raw_findings = []
        self._run_scanners = set()

        print("\n[ScanEngine] Running vulnerability scanners...")

        for url in urls:
            scanners_to_run = self._get_scanners_for_url(url)
            if not scanners_to_run:
                continue

            for scanner_name in scanners_to_run:
                if scanner_name in self._run_scanners:
                    continue
                self._run_scanners.add(scanner_name)

                try:
                    result = self.scan_engine.run_scanner(scanner_name, url)

                    if result is None:
                        continue

                    if isinstance(result, bool):
                        if result:
                            logger.warning(
                                f"Scanner {scanner_name} returned True (boolean)"
                            )
                        continue

                    if not isinstance(result, list):
                        logger.warning(
                            f"Scanner {scanner_name} returned {type(result).__name__}, expected list"
                        )
                        continue

                    if result:
                        for finding in result:
                            if isinstance(finding, dict):
                                finding["scanner_name"] = scanner_name
                                finding = self._normalize_finding(finding)

                        all_raw_findings.extend(result)

                except Exception as e:
                    logger.error(f"Scanner {scanner_name} failed: {e}")
                    if logger.isEnabledFor(logging.DEBUG):
                        traceback.print_exc()

        print(f"\n[ScanEngine] Processing {len(all_raw_findings)} raw findings...")

        if not all_raw_findings:
            print("[ScanEngine] No findings to process")
            report = self._build_empty_report(target, recon_result)
            self._print_clean_report(report)
            return report

        valid_findings = []
        for idx, finding in enumerate(all_raw_findings):
            if not isinstance(finding, dict):
                logger.warning(
                    f"Skipping finding #{idx}: not a dict ({type(finding).__name__})"
                )
                continue
            normalized = self._normalize_finding(finding)
            valid_findings.append(normalized)

        all_raw_findings = valid_findings

        # ==========================================================
        # VERIFICATION
        # ==========================================================
        verified_findings = []
        inconclusive_findings = []
        not_applicable = 0
        rejected = 0
        verification_errors = 0

        print(f"\n[Verification] Verifying {len(all_raw_findings)} findings...")

        for idx, finding in enumerate(all_raw_findings):
            if not isinstance(finding, dict):
                continue

            try:
                verified = self._verify_finding(finding)

                if isinstance(verified, dict):
                    status = verified.get("verification_status", "REJECTED")

                    if status == "VERIFIED":
                        verified_findings.append(verified)
                    elif status == "INCONCLUSIVE":
                        inconclusive_findings.append(verified)
                    elif status == "NOT_APPLICABLE":
                        not_applicable += 1
                    else:  # REJECTED
                        rejected += 1
            except Exception as exc:
                verification_errors += 1
                logger.error(f"Verification error for finding #{idx}: {exc}")
                if logger.isEnabledFor(logging.DEBUG):
                    traceback.print_exc()
                finding["verified"] = False
                finding["confidence"] = 20.0
                finding["severity"] = "Low"
                finding["verification_status"] = "ERROR"
                rejected += 1

        print(f"\n[Verification] Complete")
        print(f"  VERIFIED      : {len(verified_findings)}")
        print(f"  INCONCLUSIVE  : {len(inconclusive_findings)}")
        print(f"  REJECTED      : {rejected}")
        print(f"  NOT_APPLICABLE: {not_applicable}")
        if verification_errors > 0:
            print(f"  ERRORS        : {verification_errors}")

        # ==========================================================
        # DEDUPLICATION - FIXED: Include payload in fingerprint
        # ==========================================================
        all_valid_findings = verified_findings + inconclusive_findings
        unique_findings = []
        seen_fingerprints = set()
        for finding in all_valid_findings:
            if not isinstance(finding, dict):
                continue

            # FIX: Include payload in fingerprint
            fingerprint = (
                finding.get("type", "Unknown"),
                finding.get("url", "").split("?")[0],
                finding.get("parameter", ""),
                finding.get("payload", "")[:50],  # First 50 chars of payload
            )

            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)
                unique_findings.append(finding)

        total_valid = len(verified_findings) + len(inconclusive_findings)
        duplicates_removed = total_valid - len(unique_findings)
        print(
            f"[ScanEngine] Deduplication: {len(unique_findings)} unique (removed {max(0, duplicates_removed)} duplicates)"
        )

        # ==========================================================
        # DATABASE SAVE
        # ==========================================================
        saved_count = 0
        if unique_findings and project_id:
            print(f"[ScanEngine] Saving {len(unique_findings)} findings to database...")
            for finding in unique_findings:
                if self._save_finding_to_database(project_id, finding):
                    saved_count += 1
            print(f"[ScanEngine] Saved {saved_count} findings")

        # ==========================================================
        # REPORT
        # ==========================================================
        report = {
            "target": target,
            "recon": {
                "urls": len(urls),
                "interesting": len(recon_result.get("interesting_urls", [])),
                "parameters": len(recon_result.get("parameters", {})),
                "forms": len(recon_result.get("forms", [])),
                "technology": recon_result.get("technologies", {}).get(
                    "Server", "Unknown"
                ),
            },
            "findings": unique_findings,
            "summary": {
                "total_urls": len(urls),
                "raw_findings": len(all_raw_findings),
                "verified": len(verified_findings),
                "inconclusive": len(inconclusive_findings),
                "rejected": rejected,
                "not_applicable": not_applicable,
                "verification_errors": verification_errors,
                "duplicates_removed": max(0, duplicates_removed),
                "unique_findings": len(unique_findings),
                "saved_findings": saved_count,
                "errors": 0,
            },
            "scanner_results": self._get_scanner_summary(unique_findings),
        }

        self._print_clean_report(report)
        return report

    def _build_empty_report(self, target: str, recon_result: Dict) -> Dict:
        return {
            "target": target,
            "recon": {
                "urls": len(recon_result.get("urls", [])),
                "interesting": len(recon_result.get("interesting_urls", [])),
                "parameters": len(recon_result.get("parameters", {})),
                "forms": len(recon_result.get("forms", [])),
                "technology": recon_result.get("technologies", {}).get(
                    "Server", "Unknown"
                ),
            },
            "findings": [],
            "summary": {
                "total_urls": len(recon_result.get("urls", [])),
                "raw_findings": 0,
                "verified": 0,
                "inconclusive": 0,
                "rejected": 0,
                "not_applicable": 0,
                "verification_errors": 0,
                "duplicates_removed": 0,
                "unique_findings": 0,
                "saved_findings": 0,
                "errors": 0,
            },
            "scanner_results": {},
        }

    def _get_scanners_for_url(self, url: str) -> List[str]:
        scanners = []
        for pattern, scanner_list in self.url_scanner_map.items():
            if pattern in url:
                scanners.extend(scanner_list)
        return list(set(scanners))

    def _get_scanner_summary(self, findings: List[Dict]) -> Dict[str, int]:
        summary = defaultdict(int)
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            scanner = finding.get("scanner_name", "unknown")
            if scanner == "unknown":
                vtype = finding.get("type", "Unknown")
                summary[vtype] += 1
            else:
                summary[scanner] += 1
        return dict(summary)

    def _print_clean_report(self, report: Dict) -> None:
        """Print clean scan report."""
        print("\n" + "=" * 60)
        print("Scan Complete")
        print("=" * 60)

        summary = report.get("summary", {})
        recon = report.get("recon", {})

        print("\nReconnaissance:")
        print(f"  URLs discovered   : {recon.get('urls', 0)}")
        print(f"  Interesting URLs  : {recon.get('interesting', 0)}")
        print(f"  Parameters found  : {recon.get('parameters', 0)}")
        print(f"  Forms discovered  : {recon.get('forms', 0)}")
        print(f"  Technology        : {recon.get('technology', 'Unknown')}")

        print("\nVulnerability Scanning:")
        print(f"  Raw findings       : {summary.get('raw_findings', 0)}")
        print(f"  VERIFIED           : {summary.get('verified', 0)}")
        print(f"  INCONCLUSIVE       : {summary.get('inconclusive', 0)}")
        print(f"  REJECTED           : {summary.get('rejected', 0)}")
        print(f"  NOT_APPLICABLE     : {summary.get('not_applicable', 0)}")
        print(f"  ERRORS             : {summary.get('verification_errors', 0)}")
        print(f"  Duplicates removed : {summary.get('duplicates_removed', 0)}")
        print(f"  Unique findings    : {summary.get('unique_findings', 0)}")

        scanner_results = report.get("scanner_results", {})
        if scanner_results:
            print("\nFindings by type:")
            for scanner, count in scanner_results.items():
                print(f"  {scanner.upper()} : {count}")

        print(f"\nDatabase saved     : {summary.get('saved_findings', 0)}")
        print(f"Errors             : {summary.get('errors', 0)}")
        print("\n" + "=" * 60)
        print("SentinelAI> Scan completed successfully\n")
