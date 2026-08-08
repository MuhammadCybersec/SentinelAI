"""
Finding Processing Pipeline
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from datetime import datetime

logger = logging.getLogger(__name__)


class ConfidenceLevel(Enum):
    CRITICAL = (90, 100, "Critical")
    HIGH = (70, 89, "High")
    MEDIUM = (40, 69, "Medium")
    LOW = (0, 39, "Low")

    def __init__(self, min_score: int, max_score: int, label: str):
        self.min_score = min_score
        self.max_score = max_score
        self.label = label

    @classmethod
    def from_score(cls, score: float) -> "ConfidenceLevel":
        score_int = int(score)
        for level in cls:
            if level.min_score <= score_int <= level.max_score:
                return level
        return cls.LOW


@dataclass
class ProcessedFinding:
    vulnerability_type: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: List[str] = field(default_factory=list)
    severity: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cwe: str = ""
    owasp: str = ""
    scanner_name: str = ""
    method: str = "GET"

    fingerprint: str = ""
    confidence: float = 0.0
    confidence_level: str = "LOW"
    verified: bool = False
    verification_evidence: List[str] = field(default_factory=list)
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    status_code: int = 0
    response_time: float = 0.0
    response_length: int = 0

    discovered_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": f"{self.vulnerability_type} - {self.parameter or 'Unknown'}",
            "description": f"{self.vulnerability_type} detected at {self.url}",
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": "\n".join(self.evidence) if self.evidence else "",
            "recommendation": self.remediation,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "module": self.scanner_name,
            "target": self.url,
            "scanner_name": self.scanner_name,
            "confidence": self.confidence,
            "status": "Verified" if self.verified else "Potential",
            "is_false_positive": False,
            "verified": self.verified,
            "method": self.method,
            "status_code": self.status_code,
            "response_time": self.response_time,
        }


class FindingNormalizer:

    @staticmethod
    def normalize_url(url: str) -> str:
        if not url:
            return ""
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            return url

    @staticmethod
    def safe_get(data: Dict, key: str, default: Any = None) -> Any:
        value = data.get(key, default)
        if isinstance(value, bool) and isinstance(default, list):
            return default
        return value

    @staticmethod
    def normalize_evidence(evidence: Any) -> List[str]:
        """ALWAYS return a list of strings."""
        if evidence is None:
            return []
        if isinstance(evidence, bool):
            return ["True"] if evidence else ["False"]
        if isinstance(evidence, str):
            return [evidence] if evidence.strip() else []
        if isinstance(evidence, list):
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

    @staticmethod
    def normalize(raw_finding: Dict[str, Any]) -> ProcessedFinding:
        processed = ProcessedFinding()

        processed.vulnerability_type = FindingNormalizer.safe_get(
            raw_finding, "vulnerability_type", "Unknown"
        )
        if (
            not processed.vulnerability_type
            or processed.vulnerability_type == "Unknown"
        ):
            processed.vulnerability_type = FindingNormalizer.safe_get(
                raw_finding, "type", "Unknown"
            )

        processed.url = FindingNormalizer.safe_get(raw_finding, "url", "")
        if not processed.url:
            processed.url = FindingNormalizer.safe_get(raw_finding, "target", "")

        processed.parameter = FindingNormalizer.safe_get(raw_finding, "parameter", "")
        processed.payload = FindingNormalizer.safe_get(raw_finding, "payload", "")

        # Normalize evidence - ALWAYS returns list
        evidence = raw_finding.get("evidence")
        processed.evidence = FindingNormalizer.normalize_evidence(evidence)

        processed.severity = FindingNormalizer.safe_get(
            raw_finding, "severity", "Medium"
        )
        processed.remediation = FindingNormalizer.safe_get(
            raw_finding, "remediation", ""
        )
        processed.references = FindingNormalizer.safe_get(raw_finding, "references", [])
        if isinstance(processed.references, str):
            processed.references = [processed.references]
        if isinstance(processed.references, bool):
            processed.references = []

        processed.cwe = FindingNormalizer.safe_get(raw_finding, "cwe", "")
        processed.owasp = FindingNormalizer.safe_get(raw_finding, "owasp", "")
        processed.scanner_name = FindingNormalizer.safe_get(
            raw_finding, "scanner_name", "unknown"
        )
        processed.method = FindingNormalizer.safe_get(raw_finding, "method", "GET")
        processed.status_code = FindingNormalizer.safe_get(
            raw_finding, "status_code", 0
        )
        processed.response_time = FindingNormalizer.safe_get(
            raw_finding, "response_time", 0.0
        )
        processed.response_length = FindingNormalizer.safe_get(
            raw_finding, "response_length", 0
        )
        processed.discovered_at = datetime.utcnow()

        processed.fingerprint = FindingDeduplicator.generate_fingerprint(processed)

        return processed


class FindingDeduplicator:

    @staticmethod
    def generate_fingerprint(finding: ProcessedFinding) -> str:
        from urllib.parse import urlparse

        normalized_url = ""
        try:
            parsed = urlparse(finding.url)
            normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            normalized_url = finding.url

        fingerprint_data = {
            "vulnerability_type": finding.vulnerability_type,
            "url": normalized_url,
            "parameter": finding.parameter,
            "method": finding.method,
            "scanner": finding.scanner_name,
        }

        if finding.evidence:
            signature = str(finding.evidence[0])[:100] if finding.evidence else ""
            fingerprint_data["evidence_signature"] = signature

        fp_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.md5(fp_string.encode()).hexdigest()[:16]

    @staticmethod
    def deduplicate(findings: List[ProcessedFinding]) -> List[ProcessedFinding]:
        groups: Dict[str, List[ProcessedFinding]] = {}
        for finding in findings:
            if finding.fingerprint not in groups:
                groups[finding.fingerprint] = []
            groups[finding.fingerprint].append(finding)

        unique_findings = []
        for fingerprint, group in groups.items():
            if len(group) == 1:
                unique_findings.append(group[0])
            else:
                best = max(group, key=lambda f: (f.confidence, len(f.evidence)))
                for finding in group:
                    if finding != best:
                        finding.is_duplicate = True
                        finding.duplicate_of = best.fingerprint
                unique_findings.append(best)

        return unique_findings


class ConfidenceScorer:

    EVIDENCE_WEIGHTS = {
        "error_based": 0.45,
        "boolean_based": 0.30,
        "time_based": 0.25,
        "response_diff": 0.20,
        "status_code_diff": 0.15,
        "length_diff": 0.15,
        "dbms_fingerprint": 0.10,
        "payload_reflected": 0.25,
    }

    @classmethod
    def score(cls, finding: ProcessedFinding) -> float:
        score = 0.0

        # Ensure evidence is a list of strings
        if isinstance(finding.evidence, list):
            evidence_text = " ".join(finding.evidence).lower()
        else:
            evidence_text = str(finding.evidence).lower()

        if evidence_text:
            if any(kw in evidence_text for kw in ["error", "exception", "syntax"]):
                score += cls.EVIDENCE_WEIGHTS["error_based"]
            if any(kw in evidence_text for kw in ["true", "false", "difference"]):
                score += cls.EVIDENCE_WEIGHTS["boolean_based"]
            if any(kw in evidence_text for kw in ["delay", "sleep", "time"]):
                score += cls.EVIDENCE_WEIGHTS["time_based"]
            if "diff" in evidence_text or "difference" in evidence_text:
                score += cls.EVIDENCE_WEIGHTS["response_diff"]
            if any(
                dbms in evidence_text
                for dbms in ["mysql", "postgres", "oracle", "sqlite"]
            ):
                score += cls.EVIDENCE_WEIGHTS["dbms_fingerprint"]

        if finding.status_code and finding.status_code != 200:
            score += cls.EVIDENCE_WEIGHTS["status_code_diff"]

        if finding.response_length and finding.response_length > 100:
            score += cls.EVIDENCE_WEIGHTS["length_diff"] * 0.5

        severity_bonus = {
            "Critical": 0.15,
            "High": 0.10,
            "Medium": 0.05,
            "Low": 0.0,
        }
        score += severity_bonus.get(finding.severity, 0.0)

        return min(round(score * 100, 1), 100.0)


class FindingVerifier:

    @classmethod
    def verify(cls, finding: ProcessedFinding) -> ProcessedFinding:
        if finding.confidence >= 70:
            finding.verified = True
            finding.verification_evidence.append("High confidence score")
            return finding

        # Ensure evidence is a list of strings
        if isinstance(finding.evidence, list):
            evidence_text = " ".join(finding.evidence).lower()
        else:
            evidence_text = str(finding.evidence).lower()

        if finding.vulnerability_type == "SQL Injection":
            if any(
                kw in evidence_text for kw in ["error", "syntax", "mysql", "postgres"]
            ):
                finding.verified = True
                finding.verification_evidence.append("SQL error pattern detected")

        elif finding.vulnerability_type == "XSS":
            if any(kw in evidence_text for kw in ["<script", "alert(", "onerror"]):
                finding.verified = True
                finding.verification_evidence.append(
                    "Script tag or event handler detected"
                )

        elif finding.vulnerability_type in ["LFI", "RFI", "File Inclusion"]:
            if any(kw in evidence_text for kw in ["/etc/passwd", "root:", "/proc/"]):
                finding.verified = True
                finding.verification_evidence.append("Sensitive file content detected")

        elif finding.vulnerability_type == "SSRF":
            if any(
                kw in evidence_text for kw in ["localhost", "127.0.0.1", "internal"]
            ):
                finding.verified = True
                finding.verification_evidence.append(
                    "Internal address resolution detected"
                )

        elif finding.vulnerability_type == "Command Injection":
            if any(kw in evidence_text for kw in ["uid=", "root", "admin", "id="]):
                finding.verified = True
                finding.verification_evidence.append("Command output detected")

        if not finding.verified and finding.confidence > 40:
            finding.verification_evidence.append(
                "Potential finding requiring manual review"
            )

        finding.verified_at = datetime.utcnow()
        return finding


class FindingProcessor:

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.normalizer = FindingNormalizer()
        self.deduplicator = FindingDeduplicator()
        self.scorer = ConfidenceScorer()
        self.verifier = FindingVerifier()

        self.raw_count = 0
        self.normalized_count = 0
        self.duplicates_removed = 0
        self.verified_count = 0
        self.processed_findings: List[ProcessedFinding] = []
        self.skipped_count = 0

    def process(self, raw_findings: List[Dict[str, Any]]) -> List[ProcessedFinding]:
        """Process raw findings through the pipeline."""
        import traceback

        print(f"\n[DEBUG] ========================================")
        print(f"[DEBUG] Processing {len(raw_findings)} raw findings")
        print(f"[DEBUG] raw_findings type: {type(raw_findings).__name__}")
        print(f"[DEBUG] ========================================")

        # ==========================================================
        # DEBUG: Print each finding's structure
        # ==========================================================
        for idx, finding in enumerate(raw_findings):
            print(f"\n[DEBUG] Finding #{idx}:")
            print(f"[DEBUG]   type: {type(finding).__name__}")

            if isinstance(finding, dict):
                for key, value in finding.items():
                    value_type = type(value).__name__
                    # Truncate long values
                    value_repr = repr(value)
                    if len(value_repr) > 100:
                        value_repr = value_repr[:100] + "..."
                    print(f"[DEBUG]     {key}: {value_type} = {value_repr}")

                    # Check for boolean in fields that should be iterable
                    if isinstance(value, bool) and key in [
                        "evidence",
                        "references",
                        "tags",
                        "parameters",
                        "payloads",
                    ]:
                        print(
                            f"[DEBUG]     ⚠️ WARNING: {key} is bool! This will cause error!"
                        )
            else:
                print(f"[DEBUG]   value: {repr(finding)[:100]}")

        print(f"\n[DEBUG] ========================================")
        print(f"[DEBUG] Starting normalization...")
        print(f"[DEBUG] ========================================")

        self.raw_count = len(raw_findings)
        self.processed_findings = []
        self.skipped_count = 0

        if not raw_findings:
            if self.verbose:
                print("[VERBOSE] No raw findings to process")
            return []

        # Step 1: Normalization with detailed error tracking
        normalized = []
        for idx, raw in enumerate(raw_findings):
            try:
                print(f"[DEBUG] Normalizing finding #{idx}/{len(raw_findings)}...")

                if not isinstance(raw, dict):
                    print(f"[DEBUG] ⚠️ Skipping non-dict finding #{idx}: {type(raw)}")
                    self.skipped_count += 1
                    continue

                if not raw.get("url") and not raw.get("target"):
                    print(f"[DEBUG] ⚠️ Skipping finding #{idx}: missing URL")
                    self.skipped_count += 1
                    continue

                # Check for bool evidence BEFORE normalization
                evidence = raw.get("evidence")
                if isinstance(evidence, bool):
                    print(f"[DEBUG] ⚠️ Finding #{idx} has bool evidence: {evidence}")
                    raw["evidence"] = ["True"] if evidence else ["False"]
                    print(f"[DEBUG]    Converted to: {raw['evidence']}")

                processed = self.normalizer.normalize(raw)

                # Double-check evidence is a list
                if not isinstance(processed.evidence, list):
                    print(
                        f"[DEBUG] ⚠️ Evidence is {type(processed.evidence).__name__}, converting to list"
                    )
                    processed.evidence = (
                        [str(processed.evidence)] if processed.evidence else []
                    )

                normalized.append(processed)
                print(f"[DEBUG] ✅ Finding #{idx} normalized successfully")

            except Exception as e:
                self.skipped_count += 1
                print(f"[DEBUG] ❌ Failed to normalize finding #{idx}: {e}")
                print(f"[DEBUG]    Raw finding: {raw}")
                traceback.print_exc()
                logger.warning(f"Failed to normalize finding {idx}: {e}")

        self.normalized_count = len(normalized)

        print(f"\n[DEBUG] ========================================")
        print(
            f"[DEBUG] Normalized {self.normalized_count} findings, skipped {self.skipped_count}"
        )
        print(f"[DEBUG] ========================================")

        if not normalized:
            if self.verbose:
                print("[VERBOSE] No normalized findings to process")
            return []

        # Step 2: Confidence Scoring with debug
        print(f"[DEBUG] Starting confidence scoring...")
        for idx, finding in enumerate(normalized):
            try:
                print(f"[DEBUG] Scoring finding #{idx}...")
                finding.confidence = self.scorer.score(finding)
                finding.confidence_level = ConfidenceLevel.from_score(
                    finding.confidence
                ).label
                print(f"[DEBUG]   Confidence: {finding.confidence}")
            except Exception as e:
                print(f"[DEBUG] ❌ Confidence scoring failed for finding #{idx}: {e}")
                traceback.print_exc()
                finding.confidence = 0.0
                finding.confidence_level = "LOW"

        # Step 3: Verification with debug
        print(f"[DEBUG] Starting verification...")
        for idx, finding in enumerate(normalized):
            try:
                print(f"[DEBUG] Verifying finding #{idx}...")
                finding = self.verifier.verify(finding)
                if finding.verified:
                    self.verified_count += 1
                    print(f"[DEBUG]   ✅ Verified")
                else:
                    print(f"[DEBUG]   ❌ Not verified")
            except Exception as e:
                print(f"[DEBUG] ❌ Verification failed for finding #{idx}: {e}")
                traceback.print_exc()
                finding.verified = False

        # Step 4: Deduplication with debug
        print(f"[DEBUG] Starting deduplication...")
        try:
            unique = self.deduplicator.deduplicate(normalized)
            self.duplicates_removed = self.normalized_count - len(unique)
            print(
                f"[DEBUG] Deduplicated: {len(unique)} unique from {self.normalized_count}"
            )
        except Exception as e:
            print(f"[DEBUG] ❌ Deduplication failed: {e}")
            traceback.print_exc()
            unique = normalized
            self.duplicates_removed = 0

        self.processed_findings = unique

        print(f"\n[DEBUG] ========================================")
        print(f"[DEBUG] Processing complete: {len(unique)} findings")
        print(f"[DEBUG] ========================================")

        return unique

    def get_summary(self) -> Dict[str, Any]:
        return {
            "raw_findings": self.raw_count,
            "normalized": self.normalized_count,
            "skipped": self.skipped_count,
            "duplicates_removed": self.duplicates_removed,
            "verified_findings": self.verified_count,
            "final_findings": len(self.processed_findings),
            "by_confidence": {
                "critical": len(
                    [
                        f
                        for f in self.processed_findings
                        if f.confidence_level == "Critical"
                    ]
                ),
                "high": len(
                    [f for f in self.processed_findings if f.confidence_level == "High"]
                ),
                "medium": len(
                    [
                        f
                        for f in self.processed_findings
                        if f.confidence_level == "Medium"
                    ]
                ),
                "low": len(
                    [f for f in self.processed_findings if f.confidence_level == "Low"]
                ),
            },
            "by_verified": {
                "verified": len([f for f in self.processed_findings if f.verified]),
                "potential": len(
                    [f for f in self.processed_findings if not f.verified]
                ),
            },
            "by_type": self._get_type_summary(),
        }

    def _get_type_summary(self) -> Dict[str, int]:
        summary = {}
        for finding in self.processed_findings:
            vtype = finding.vulnerability_type
            summary[vtype] = summary.get(vtype, 0) + 1
        return summary
