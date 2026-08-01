"""
Phase 20: AI Attack Planner & Exploitation Orchestrator for SentinelAI.

Enterprise-grade intelligent attack planning engine that:
- Analyzes all detection results
- Automatically selects optimal exploitation strategy
- Provides fallback strategies
- Recommends tamper scripts
- Estimates requests and duration
- Calculates risk levels
- Provides reasoning for decisions

Strategy Priority:
1. UNION (if available and stable)
2. Error-Based (if available)
3. Boolean Blind (if available)
4. Time Blind (if available)
5. OOB (if available)
6. Stop (if no technique available)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .blind_boolean import BlindBooleanResult
from .blind_extractor import BlindExtractionResult
from .blind_time import TimeBlindResult
from .column_detector import ColumnDetectionResult
from .datatype_detector import DataTypeDetectionResult
from .error_based import ErrorBasedResult
from .oob_exploiter import OOBExploitResult
from .oracle_database import OracleDatabaseResult
from .oracle_privileges import OraclePrivilegeResult
from .oracle_schema import OracleSchemaResult
from .oracle_version import OracleVersionResult
from .sqli_detector import SQLiDetectionResult
from .tamper_engine import TamperEngine
from .waf_detector import WAFDetectionResult


class ExploitationStrategy(Enum):
    """Available exploitation strategies."""

    UNION = "union"
    ERROR_BASED = "error_based"
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BLIND = "time_blind"
    OOB_DNS = "oob_dns"
    OOB_HTTP = "oob_http"
    OOB_LDAP = "oob_ldap"
    OOB_XXE = "oob_xxe"
    HYBRID = "hybrid"
    STOP = "stop"


class RiskLevel(Enum):
    """Risk level of exploitation strategy."""

    LOW = "low"  # Low risk, high confidence
    MEDIUM = "medium"  # Moderate risk, moderate confidence
    HIGH = "high"  # High risk, low confidence
    CRITICAL = "critical"  # Very high risk, very low confidence


@dataclass
class AttackPlanResult:
    """
    Result of the attack planning process.

    Attributes:
        success: Whether a valid plan was created
        selected_strategy: Primary strategy to use
        fallback_strategy: Backup strategy if primary fails
        confidence: Confidence in the plan (0-100)
        recommended_tampers: List of tamper scripts to apply
        execution_order: Ordered list of strategies to try
        estimated_requests: Estimated number of requests
        estimated_duration: Estimated duration in seconds
        risk_level: Risk level of the plan
        reasoning: Reasoning behind the decision
        metadata: Additional metadata
        created_at: When the plan was created
    """

    success: bool = False
    selected_strategy: ExploitationStrategy | None = None
    fallback_strategy: ExploitationStrategy | None = None
    confidence: float = 0.0
    recommended_tampers: list[str] = field(default_factory=list)
    execution_order: list[ExploitationStrategy] = field(default_factory=list)
    estimated_requests: int = 0
    estimated_duration: float = 0.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    reasoning: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "selected_strategy": (
                self.selected_strategy.value if self.selected_strategy else None
            ),
            "fallback_strategy": (
                self.fallback_strategy.value if self.fallback_strategy else None
            ),
            "confidence": self.confidence,
            "recommended_tampers": self.recommended_tampers,
            "execution_order": [s.value for s in self.execution_order],
            "estimated_requests": self.estimated_requests,
            "estimated_duration": self.estimated_duration,
            "risk_level": self.risk_level.value,
            "reasoning": self.reasoning,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }

    def get_summary(self) -> str:
        """Get a human-readable summary of the attack plan."""
        summary_lines = [
            "Attack Plan Summary:",
            f"  Strategy: {self.selected_strategy.value if self.selected_strategy else 'None'}",
            f"  Fallback: {self.fallback_strategy.value if self.fallback_strategy else 'None'}",
            f"  Confidence: {self.confidence:.1f}%",
            f"  Risk Level: {self.risk_level.value.upper()}",
            f"  Estimated Requests: {self.estimated_requests}",
            f"  Estimated Duration: {self.estimated_duration:.1f}s",
            f"  Recommended Tampers: {', '.join(self.recommended_tampers) if self.recommended_tampers else 'None'}",
        ]
        if self.reasoning:
            summary_lines.append("  Reasoning:")
            for reason in self.reasoning[:5]:
                summary_lines.append(f"    - {reason}")
        return "\n".join(summary_lines)


class AttackPlanner:
    """
    AI Attack Planner & Exploitation Orchestrator.

    Analyzes detection results and creates optimal exploitation plans.
    """

    # Priority weights for different strategies
    STRATEGY_PRIORITY = {
        ExploitationStrategy.UNION: 100,
        ExploitationStrategy.ERROR_BASED: 90,
        ExploitationStrategy.BOOLEAN_BLIND: 80,
        ExploitationStrategy.TIME_BLIND: 70,
        ExploitationStrategy.OOB_HTTP: 60,
        ExploitationStrategy.OOB_DNS: 55,
        ExploitationStrategy.OOB_XXE: 50,
        ExploitationStrategy.OOB_LDAP: 45,
        ExploitationStrategy.HYBRID: 40,
        ExploitationStrategy.STOP: 0,
    }

    # Risk multipliers based on strategy
    RISK_MULTIPLIERS = {
        ExploitationStrategy.UNION: 0.2,
        ExploitationStrategy.ERROR_BASED: 0.3,
        ExploitationStrategy.BOOLEAN_BLIND: 0.5,
        ExploitationStrategy.TIME_BLIND: 0.6,
        ExploitationStrategy.OOB_HTTP: 0.7,
        ExploitationStrategy.OOB_DNS: 0.65,
        ExploitationStrategy.OOB_XXE: 0.75,
        ExploitationStrategy.OOB_LDAP: 0.8,
        ExploitationStrategy.HYBRID: 0.9,
        ExploitationStrategy.STOP: 1.0,
    }

    # Estimated requests per strategy (approximate)
    ESTIMATED_REQUESTS = {
        ExploitationStrategy.UNION: 10,
        ExploitationStrategy.ERROR_BASED: 20,
        ExploitationStrategy.BOOLEAN_BLIND: 500,
        ExploitationStrategy.TIME_BLIND: 1000,
        ExploitationStrategy.OOB_HTTP: 50,
        ExploitationStrategy.OOB_DNS: 100,
        ExploitationStrategy.OOB_XXE: 60,
        ExploitationStrategy.OOB_LDAP: 80,
        ExploitationStrategy.HYBRID: 300,
        ExploitationStrategy.STOP: 0,
    }
    # WAF risk multiplier
    WAF_RISK_MULTIPLIER = 2.0

    def __init__(
        self,
        logger: logging.Logger | None = None,
        tamper_engine: TamperEngine | None = None,
        max_estimated_requests: int = 10000,
        default_timeout: float = 30.0,
        confidence_threshold: float = 70.0,
    ):
        """
        Initialize the Attack Planner.

        Args:
            logger: Optional logger instance
            tamper_engine: Optional tamper engine for recommendations
            max_estimated_requests: Maximum estimated requests to consider
            default_timeout: Default timeout in seconds
            confidence_threshold: Minimum confidence to proceed (0-100)
        """
        self.logger = logger or self._setup_logger()
        self.tamper_engine = tamper_engine or TamperEngine(logger)
        self.max_estimated_requests = max_estimated_requests
        self.default_timeout = default_timeout
        self.confidence_threshold = confidence_threshold

        self.logger.info("[AttackPlanner] Initialized")
        self.logger.info(
            f"[AttackPlanner] Confidence threshold: {confidence_threshold}%"
        )

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("AttackPlanner")
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

    # ============================================================
    # CORE PLANNING LOGIC
    # ============================================================

    def plan_attack(
        self,
        injection_point: str,
        version_result: OracleVersionResult | None = None,
        schema_result: OracleSchemaResult | None = None,
        privilege_result: OraclePrivilegeResult | None = None,
        database_result: OracleDatabaseResult | None = None,
        sqli_result: SQLiDetectionResult | None = None,
        column_result: ColumnDetectionResult | None = None,
        datatype_result: DataTypeDetectionResult | None = None,
        blind_boolean_result: BlindBooleanResult | None = None,
        time_blind_result: TimeBlindResult | None = None,
        error_based_result: ErrorBasedResult | None = None,
        waf_result: WAFDetectionResult | None = None,
        blind_extract_result: BlindExtractionResult | None = None,
        oob_result: OOBExploitResult | None = None,
        **kwargs,
    ) -> AttackPlanResult:
        """
        Create an optimal attack plan based on all detection results.
        """
        self.logger.info("[AttackPlanner] Creating attack plan...")
        self.logger.info(f"[AttackPlanner] Injection point: {injection_point}")

        result = AttackPlanResult()
        result.metadata = {
            "injection_point": injection_point,
            "timestamp": datetime.now().isoformat(),
        }

        # Analyze all available results
        strategy_scores = self._score_strategies(
            version_result=version_result,
            schema_result=schema_result,
            privilege_result=privilege_result,
            database_result=database_result,
            sqli_result=sqli_result,
            column_result=column_result,
            datatype_result=datatype_result,
            blind_boolean_result=blind_boolean_result,
            time_blind_result=time_blind_result,
            error_based_result=error_based_result,
            waf_result=waf_result,
            blind_extract_result=blind_extract_result,
            oob_result=oob_result,
        )

        # Sort strategies by score
        sorted_strategies = sorted(
            strategy_scores.items(), key=lambda x: x[1], reverse=True
        )

        # Select the best strategy
        if sorted_strategies and sorted_strategies[0][1] > 0:
            best_strategy, best_score = sorted_strategies[0]
            result.selected_strategy = best_strategy
            result.confidence = min(100.0, best_score)

            # Select fallback
            if len(sorted_strategies) > 1:
                fallback_strategy, fallback_score = sorted_strategies[1]
                result.fallback_strategy = fallback_strategy

            # Build execution order
            result.execution_order = [
                strategy for strategy, score in sorted_strategies if score > 0
            ]

            # Calculate estimates
            result.estimated_requests = self._estimate_requests(
                result.selected_strategy
            )
            result.estimated_duration = self._estimate_duration(
                result.selected_strategy
            )

            # Determine risk level
            result.risk_level = self._calculate_risk_level(
                result.selected_strategy, waf_result, result.confidence
            )

            # Get tamper recommendations
            result.recommended_tampers = self._recommend_tampers(
                result.selected_strategy, waf_result
            )

            # Build reasoning
            result.reasoning = self._build_reasoning(
                result.selected_strategy, strategy_scores, waf_result, result.confidence
            )

            result.success = True

        else:
            result.selected_strategy = ExploitationStrategy.STOP
            result.success = False
            result.reasoning = ["No viable exploitation strategy found"]
            # Add WAF reasoning if WAF was detected
            if waf_result and waf_result.waf_detected:
                result.reasoning.append(
                    f"WAF detected: {waf_result.waf_name or 'Unknown'} (Confidence: {waf_result.confidence}%)"
                )

        self.logger.info(f"[AttackPlanner] Plan complete: {result.get_summary()}")
        return result

    # ============================================================
    # STRATEGY SCORING
    # ============================================================

    def _score_strategies(
        self,
        version_result: OracleVersionResult | None = None,
        schema_result: OracleSchemaResult | None = None,
        privilege_result: OraclePrivilegeResult | None = None,
        database_result: OracleDatabaseResult | None = None,
        sqli_result: SQLiDetectionResult | None = None,
        column_result: ColumnDetectionResult | None = None,
        datatype_result: DataTypeDetectionResult | None = None,
        blind_boolean_result: BlindBooleanResult | None = None,
        time_blind_result: TimeBlindResult | None = None,
        error_based_result: ErrorBasedResult | None = None,
        waf_result: WAFDetectionResult | None = None,
        blind_extract_result: BlindExtractionResult | None = None,
        oob_result: OOBExploitResult | None = None,
    ) -> dict[ExploitationStrategy, float]:
        """
        Score each strategy based on available results.

        Returns:
            Dict[ExploitationStrategy, float]: Strategy -> score mapping
        """
        scores = {strategy: 0.0 for strategy in ExploitationStrategy}

        # Score UNION strategy
        scores[ExploitationStrategy.UNION] = self._score_union(
            sqli_result, column_result, datatype_result, waf_result
        )

        # Score Error-Based strategy
        scores[ExploitationStrategy.ERROR_BASED] = self._score_error_based(
            sqli_result, error_based_result, waf_result
        )

        # Score Boolean Blind strategy
        scores[ExploitationStrategy.BOOLEAN_BLIND] = self._score_boolean_blind(
            sqli_result, blind_boolean_result, waf_result
        )

        # Score Time Blind strategy
        scores[ExploitationStrategy.TIME_BLIND] = self._score_time_blind(
            sqli_result, time_blind_result, waf_result
        )

        # Score OOB strategies
        oob_scores = self._score_oob(oob_result, waf_result)
        scores.update(oob_scores)

        # Score Hybrid strategy
        scores[ExploitationStrategy.HYBRID] = self._score_hybrid(scores)

        # Apply WAF penalties
        if waf_result and waf_result.waf_detected:
            scores = self._apply_waf_penalties(scores, waf_result)

        # Apply privilege penalties
        if privilege_result:
            scores = self._apply_privilege_penalties(scores, privilege_result)

        return scores

    def _score_union(
        self,
        sqli_result: SQLiDetectionResult | None,
        column_result: ColumnDetectionResult | None,
        datatype_result: DataTypeDetectionResult | None,
        waf_result: WAFDetectionResult | None,
    ) -> float:
        """Score UNION strategy."""
        score = 0.0

        # Check if UNION injection is detected
        if sqli_result and sqli_result.union_injection_detected:
            score += 40

        # Check column count
        if column_result and column_result.success and column_result.column_count > 0:
            score += 30

        # Check reflective columns
        if column_result and column_result.reflective_columns:
            score += 20

        # Check data types
        if datatype_result and datatype_result.success:
            score += 10

        # Penalize if WAF is detected (UNION is often blocked)
        if waf_result and waf_result.waf_detected:
            score *= 0.4

        return min(100.0, score)

    def _score_error_based(
        self,
        sqli_result: SQLiDetectionResult | None,
        error_based_result: ErrorBasedResult | None,
        waf_result: WAFDetectionResult | None,
    ) -> float:
        """Score Error-Based strategy."""
        score = 0.0

        # Check if error-based injection is detected
        if sqli_result and sqli_result.error_based_detected:
            score += 50

        # Check error-based result
        if error_based_result:
            if error_based_result.is_vulnerable:
                score += 40
            if error_based_result.extracted_values:
                score += 10

        # WAF penalty (WAF often blocks error messages)
        if waf_result and waf_result.waf_detected:
            score *= 0.5

        return min(100.0, score)

    def _score_boolean_blind(
        self,
        sqli_result: SQLiDetectionResult | None,
        blind_boolean_result: BlindBooleanResult | None,
        waf_result: WAFDetectionResult | None,
    ) -> float:
        """Score Boolean Blind strategy."""
        score = 0.0

        # Check if blind injection is detected
        if sqli_result and sqli_result.blind_injection_detected:
            score += 30

        # Check boolean blind result
        if blind_boolean_result:
            if blind_boolean_result.is_vulnerable:
                score += 50
            if blind_boolean_result.working_payloads:
                score += 20

        # WAF penalty (WAF can interfere with blind detection)
        if waf_result and waf_result.waf_detected:
            score *= 0.7

        return min(100.0, score)

    def _score_time_blind(
        self,
        sqli_result: SQLiDetectionResult | None,
        time_blind_result: TimeBlindResult | None,
        waf_result: WAFDetectionResult | None,
    ) -> float:
        """Score Time Blind strategy."""
        score = 0.0

        # Check if time blind injection is detected
        if sqli_result and sqli_result.time_based_detected:
            score += 30

        # Check time blind result
        if time_blind_result:
            if time_blind_result.is_vulnerable:
                score += 50
            if time_blind_result.delay_seconds > 0:
                score += 20

        # WAF penalty (time-based can be slow and may be blocked)
        if waf_result and waf_result.waf_detected:
            score *= 0.6

        return min(100.0, score)

    def _score_oob(
        self,
        oob_result: OOBExploitResult | None,
        waf_result: WAFDetectionResult | None,
    ) -> dict[ExploitationStrategy, float]:
        """Score OOB strategies."""
        scores = {
            ExploitationStrategy.OOB_DNS: 0.0,
            ExploitationStrategy.OOB_HTTP: 0.0,
            ExploitationStrategy.OOB_LDAP: 0.0,
            ExploitationStrategy.OOB_XXE: 0.0,
        }

        if not oob_result:
            return scores

        # Check if OOB result is successful and has a technique
        if oob_result.success and oob_result.technique:
            technique_value = oob_result.technique.value

            # DNS OOB
            if technique_value in ["dns", "dns_chunked"]:
                scores[ExploitationStrategy.OOB_DNS] = 50 + (oob_result.confidence / 2)

            # HTTP OOB
            if technique_value in ["http", "utl_http"]:
                scores[ExploitationStrategy.OOB_HTTP] = 60 + (oob_result.confidence / 2)

            # LDAP OOB
            if technique_value == "dbms_ldap":
                scores[ExploitationStrategy.OOB_LDAP] = 40 + (oob_result.confidence / 2)

            # XXE OOB
            if technique_value in ["xxe", "xml_extract"]:
                scores[ExploitationStrategy.OOB_XXE] = 45 + (oob_result.confidence / 2)

        # Also check if OOB was detected as available even without successful exploitation
        if oob_result.callbacks_received > 0:
            # If we received callbacks, boost scores
            scores[ExploitationStrategy.OOB_HTTP] = max(
                scores[ExploitationStrategy.OOB_HTTP], 40
            )
            scores[ExploitationStrategy.OOB_DNS] = max(
                scores[ExploitationStrategy.OOB_DNS], 35
            )

        # WAF penalty (OOB can sometimes bypass WAF)
        if waf_result and waf_result.waf_detected:
            for strategy in scores:
                if scores[strategy] > 0:
                    scores[strategy] *= 0.8

        return scores

    def _score_hybrid(self, scores: dict[ExploitationStrategy, float]) -> float:
        """Score Hybrid strategy (combination of multiple)."""
        # Take the best two scores and average them
        sorted_scores = sorted(scores.values(), reverse=True)
        if len(sorted_scores) >= 2 and sorted_scores[0] > 0:
            return (sorted_scores[0] + sorted_scores[1]) / 2
        return 0.0

    def _apply_waf_penalties(
        self, scores: dict[ExploitationStrategy, float], waf_result: WAFDetectionResult
    ) -> dict[ExploitationStrategy, float]:
        """Apply penalties based on WAF detection."""
        # High confidence WAF detection = higher penalties
        penalty_factor = 1.0 - (waf_result.confidence / 100.0) * 0.5

        for strategy in scores:
            if strategy in [
                ExploitationStrategy.UNION,
                ExploitationStrategy.ERROR_BASED,
            ]:
                scores[strategy] *= penalty_factor

        return scores

    def _apply_privilege_penalties(
        self,
        scores: dict[ExploitationStrategy, float],
        privilege_result: OraclePrivilegeResult,
    ) -> dict[ExploitationStrategy, float]:
        """Apply penalties based on privilege results."""
        # Some strategies require more privileges
        if privilege_result.is_dba:
            # DBA privileges improve all strategies
            for strategy in scores:
                scores[strategy] *= 1.1
        else:
            # Limited privileges hurt some strategies
            for strategy in [
                ExploitationStrategy.OOB_DNS,
                ExploitationStrategy.OOB_LDAP,
            ]:
                scores[strategy] *= 0.7

        return scores

    # ============================================================
    # ESTIMATION METHODS
    # ============================================================

    def _estimate_requests(self, strategy: ExploitationStrategy) -> int:
        """Estimate number of requests for a strategy."""
        base_requests = self.ESTIMATED_REQUESTS.get(strategy, 100)

        # Only add tamper overhead if tampers are actually recommended
        # Check if tampers would be applied for this strategy
        if self._has_tampers(strategy):
            base_requests = int(base_requests * 1.2)

        return min(base_requests, self.max_estimated_requests)

    def _estimate_duration(self, strategy: ExploitationStrategy) -> float:
        """Estimate duration in seconds for a strategy."""
        base_requests = self._estimate_requests(strategy)

        # Different strategies have different per-request durations
        per_request_duration = {
            ExploitationStrategy.UNION: 0.5,
            ExploitationStrategy.ERROR_BASED: 1.0,
            ExploitationStrategy.BOOLEAN_BLIND: 1.5,
            ExploitationStrategy.TIME_BLIND: 3.0,
            ExploitationStrategy.OOB_DNS: 2.0,
            ExploitationStrategy.OOB_HTTP: 1.0,
            ExploitationStrategy.OOB_LDAP: 2.5,
            ExploitationStrategy.OOB_XXE: 1.5,
            ExploitationStrategy.HYBRID: 2.0,
            ExploitationStrategy.STOP: 0.0,
        }

        duration = base_requests * per_request_duration.get(strategy, 1.0)

        # Add network latency overhead
        duration *= 1.2

        return min(duration, 3600)  # Cap at 1 hour

    def _calculate_risk_level(
        self,
        strategy: ExploitationStrategy,
        waf_result: WAFDetectionResult | None,
        confidence: float,
    ) -> RiskLevel:
        """Calculate risk level for a strategy."""
        base_risk = self.RISK_MULTIPLIERS.get(strategy, 0.5)

        # Increase risk if WAF is detected (multiply by WAF_RISK_MULTIPLIER)
        if waf_result and waf_result.waf_detected:
            base_risk *= self.WAF_RISK_MULTIPLIER

        # Decrease risk with higher confidence
        confidence_factor = 1.0 - (confidence / 200.0)
        risk = base_risk * max(0.1, confidence_factor)

        # Determine risk level
        if risk < 0.3:
            return RiskLevel.LOW
        elif risk < 0.5:
            return RiskLevel.MEDIUM
        elif risk < 0.7:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    # ============================================================
    # TAMPER RECOMMENDATIONS
    # ============================================================

    def _recommend_tampers(
        self, strategy: ExploitationStrategy, waf_result: WAFDetectionResult | None
    ) -> list[str]:
        """Recommend tamper scripts based on strategy and WAF."""
        tampers = []

        # Add WAF-specific tampers
        if waf_result and waf_result.waf_detected and waf_result.waf_name:
            waf_tampers = self.tamper_engine.recommend_tampers(waf_result.waf_name)
            tampers.extend(waf_tampers)

        # Add strategy-specific tampers
        if strategy == ExploitationStrategy.UNION:
            tampers.extend(["space_to_comment", "keyword_split"])
        elif strategy == ExploitationStrategy.ERROR_BASED:
            tampers.extend(["char_encode", "mixed_encoding"])
        elif strategy in [
            ExploitationStrategy.BOOLEAN_BLIND,
            ExploitationStrategy.TIME_BLIND,
        ]:
            tampers.extend(["space_to_newline", "random_case"])
        elif strategy in [ExploitationStrategy.OOB_DNS, ExploitationStrategy.OOB_HTTP]:
            tampers.extend(["percentage_encode", "double_url_encode"])

        # Remove duplicates
        return list(dict.fromkeys(tampers))

    def _has_tampers(self, strategy: ExploitationStrategy) -> bool:
        """Check if a strategy typically uses tampers."""
        # Only return True for strategies that would actually use tampers
        # This is a simple check - in production it would be more sophisticated
        return strategy in [
            ExploitationStrategy.UNION,
            ExploitationStrategy.ERROR_BASED,
            ExploitationStrategy.BOOLEAN_BLIND,
            ExploitationStrategy.TIME_BLIND,
        ]

    # ============================================================
    # REASONING
    # ============================================================

    def _build_reasoning(
        self,
        strategy: ExploitationStrategy,
        scores: dict[ExploitationStrategy, float],
        waf_result: WAFDetectionResult | None,
        confidence: float,
    ) -> list[str]:
        """Build reasoning for the selected plan."""
        reasoning = []

        # Strategy selection reason
        reasoning.append(
            f"Selected {strategy.value} with score {scores.get(strategy, 0):.1f}"
        )

        # Confidence reason
        reasoning.append(f"Confidence: {confidence:.1f}%")

        # WAF reason
        if waf_result and waf_result.waf_detected:
            reasoning.append(
                f"WAF detected: {waf_result.waf_name or 'Unknown'} (Confidence: {waf_result.confidence}%)"
            )
            if waf_result.bypass_recommendations:
                reasoning.append("WAF bypass recommendations available")
        else:
            reasoning.append("No WAF detected")

        # Alternative strategies
        alt_strategies = [
            (s, score) for s, score in scores.items() if s != strategy and score > 0
        ]
        alt_strategies.sort(key=lambda x: x[1], reverse=True)
        if alt_strategies:
            alt_str = ", ".join(
                [f"{s.value} ({score:.1f})" for s, score in alt_strategies[:3]]
            )
            reasoning.append(f"Alternative strategies: {alt_str}")

        # Risk assessment
        risk_level = self._calculate_risk_level(strategy, waf_result, confidence)
        reasoning.append(f"Risk level: {risk_level.value.upper()}")

        # Tamper recommendation
        tampers = self._recommend_tampers(strategy, waf_result)
        if tampers:
            reasoning.append(f"Recommended tampers: {', '.join(tampers)}")

        return reasoning

    # ============================================================
    # EXECUTION PLANNING
    # ============================================================

    def execute_plan(
        self, plan: AttackPlanResult, execution_function: callable, **kwargs
    ) -> dict[str, Any]:
        """
        Execute a given attack plan.

        Args:
            plan: The attack plan to execute
            execution_function: Function to execute for each strategy
            **kwargs: Additional arguments for execution

        Returns:
            Dict[str, Any]: Execution results
        """
        self.logger.info("[AttackPlanner] Executing attack plan...")

        results = {
            "success": False,
            "strategy_used": None,
            "data": None,
            "errors": [],
            "attempts": [],
        }

        if not plan.success or not plan.execution_order:
            results["errors"].append("Invalid plan or no strategies to execute")
            return results

        # Execute strategies in order
        for strategy in plan.execution_order:
            self.logger.info(f"[AttackPlanner] Executing strategy: {strategy.value}")

            try:
                # Apply tampers if recommended
                tampers = (
                    plan.recommended_tampers
                    if strategy == plan.selected_strategy
                    else []
                )

                result = execution_function(
                    strategy=strategy, tampers=tampers, **kwargs
                )

                results["attempts"].append(
                    {
                        "strategy": strategy.value,
                        "success": result.get("success", False),
                        "data": result.get("data"),
                        "error": result.get("error"),
                    }
                )

                if result.get("success"):
                    results["success"] = True
                    results["strategy_used"] = strategy
                    results["data"] = result.get("data")
                    self.logger.info(
                        f"[AttackPlanner] Strategy {strategy.value} succeeded!"
                    )
                    break
                else:
                    self.logger.warning(
                        f"[AttackPlanner] Strategy {strategy.value} failed"
                    )

            except Exception as e:
                self.logger.error(
                    f"[AttackPlanner] Strategy {strategy.value} error: {e!s}"
                )
                results["errors"].append(f"{strategy.value}: {e!s}")

                results["attempts"].append(
                    {"strategy": strategy.value, "success": False, "error": str(e)}
                )

        if not results["success"]:
            # Try fallback strategy
            if plan.fallback_strategy:
                self.logger.info(
                    f"[AttackPlanner] Trying fallback: {plan.fallback_strategy.value}"
                )
                try:
                    result = execution_function(
                        strategy=plan.fallback_strategy,
                        tampers=plan.recommended_tampers,
                        **kwargs,
                    )
                    if result.get("success"):
                        results["success"] = True
                        results["strategy_used"] = plan.fallback_strategy
                        results["data"] = result.get("data")
                except Exception as e:
                    results["errors"].append(f"Fallback failed: {e!s}")

        return results

    def auto_exploit(
        self,
        injection_point: str,
        execution_function: callable,
        detection_results: dict[str, Any],
        **kwargs,
    ) -> dict[str, Any]:
        """
        Fully automatic exploitation - plan and execute.

        Args:
            injection_point: Parameter to inject into
            execution_function: Function to execute strategies
            detection_results: Dictionary of detection results
            **kwargs: Additional arguments

        Returns:
            Dict[str, Any]: Execution results
        """
        self.logger.info("[AttackPlanner] Starting automatic exploitation...")

        # Create a plan
        plan = self.plan_attack(injection_point, **detection_results)

        if not plan.success:
            return {
                "success": False,
                "error": "No viable exploitation strategy found",
                "plan": plan.to_dict(),
            }

        # Execute the plan
        execution_results = self.execute_plan(plan, execution_function, **kwargs)
        execution_results["plan"] = plan.to_dict()

        return execution_results

    # ============================================================
    # UTILITY METHODS
    # ============================================================

    def get_strategy_score(self, strategy: ExploitationStrategy) -> int:
        """Get the priority score for a strategy."""
        return self.STRATEGY_PRIORITY.get(strategy, 0)

    def get_available_strategies(self) -> list[ExploitationStrategy]:
        """Get all available strategies."""
        return list(ExploitationStrategy)

    def validate_plan(self, plan: AttackPlanResult) -> bool:
        """Validate an attack plan."""
        if not plan.success:
            return False

        if plan.selected_strategy is None:
            return False

        if plan.selected_strategy == ExploitationStrategy.STOP:
            return False

        if plan.confidence < self.confidence_threshold:
            self.logger.warning(
                f"[AttackPlanner] Plan confidence {plan.confidence}% below threshold"
            )
            return False

        return True
