# tests/test_attack_planner.py - Complete Fixed Version

"""
Unit tests for Phase 20: AI Attack Planner & Exploitation Orchestrator.
"""

import logging
import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.attack_planner import (
    AttackPlanner,
    AttackPlanResult,
    ExploitationStrategy,
    RiskLevel,
)
from app.modules.scanner.oob_exploiter import OOBTechnique


class TestAttackPlanResult(unittest.TestCase):
    """Test AttackPlanResult dataclass."""

    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_result_initialization(self):
        """Test result initialization."""
        result = AttackPlanResult()
        self.assertFalse(result.success)
        self.assertIsNone(result.selected_strategy)
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.reasoning, [])
        self.assertEqual(result.risk_level, RiskLevel.MEDIUM)

    def test_result_with_values(self):
        """Test result with custom values."""
        result = AttackPlanResult(
            success=True,
            selected_strategy=ExploitationStrategy.UNION,
            fallback_strategy=ExploitationStrategy.ERROR_BASED,
            confidence=95.0,
            recommended_tampers=["space_to_comment"],
            execution_order=[
                ExploitationStrategy.UNION,
                ExploitationStrategy.ERROR_BASED,
            ],
            estimated_requests=10,
            estimated_duration=5.0,
            risk_level=RiskLevel.LOW,
            reasoning=["UNION is available", "High confidence"],
        )
        self.assertTrue(result.success)
        self.assertEqual(result.selected_strategy, ExploitationStrategy.UNION)
        self.assertEqual(result.confidence, 95.0)
        self.assertEqual(len(result.reasoning), 2)

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = AttackPlanResult(
            success=True,
            selected_strategy=ExploitationStrategy.BOOLEAN_BLIND,
            confidence=85.0,
            estimated_requests=500,
            estimated_duration=300.0,
        )
        result_dict = result.to_dict()

        self.assertEqual(result_dict["success"], True)
        self.assertEqual(result_dict["selected_strategy"], "boolean_blind")
        self.assertEqual(result_dict["confidence"], 85.0)
        self.assertEqual(result_dict["estimated_requests"], 500)
        self.assertEqual(result_dict["estimated_duration"], 300.0)

    def test_get_summary_success(self):
        """Test summary generation on success."""
        result = AttackPlanResult(
            success=True,
            selected_strategy=ExploitationStrategy.UNION,
            fallback_strategy=ExploitationStrategy.ERROR_BASED,
            confidence=95.0,
            recommended_tampers=["space_to_comment", "keyword_split"],
            estimated_requests=10,
            estimated_duration=5.0,
            risk_level=RiskLevel.LOW,
        )
        summary = result.get_summary()
        self.assertIn("Strategy: union", summary)
        self.assertIn("Fallback: error_based", summary)
        self.assertIn("Confidence: 95.0%", summary)
        self.assertIn("Risk Level: LOW", summary)
        self.assertIn("space_to_comment", summary)

    def test_get_summary_failure(self):
        """Test summary generation on failure."""
        result = AttackPlanResult(success=False, reasoning=["No viable strategy found"])
        summary = result.get_summary()
        self.assertIn("Strategy: None", summary)
        self.assertIn("Reasoning:", summary)


class TestAttackPlanner(unittest.TestCase):
    """Test AttackPlanner class."""

    def setUp(self):
        """Set up test environment."""
        logging.disable(logging.CRITICAL)
        self.planner = AttackPlanner(confidence_threshold=70.0)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_initialization(self):
        """Test planner initialization."""
        self.assertEqual(self.planner.confidence_threshold, 70.0)
        self.assertEqual(self.planner.max_estimated_requests, 10000)
        self.assertIsNotNone(self.planner.tamper_engine)

    def test_get_strategy_score(self):
        """Test getting strategy priority scores."""
        self.assertEqual(
            self.planner.get_strategy_score(ExploitationStrategy.UNION), 100
        )
        self.assertEqual(self.planner.get_strategy_score(ExploitationStrategy.STOP), 0)

    def test_get_available_strategies(self):
        """Test getting available strategies."""
        strategies = self.planner.get_available_strategies()
        self.assertIn(ExploitationStrategy.UNION, strategies)
        self.assertIn(ExploitationStrategy.STOP, strategies)
        self.assertGreater(len(strategies), 5)

    def test_estimate_requests(self):
        """Test request estimation."""
        # Without tamper overhead (mock _has_tampers to return False)
        with patch.object(self.planner, "_has_tampers") as mock_has:
            mock_has.return_value = False
            requests = self.planner._estimate_requests(ExploitationStrategy.UNION)
            self.assertEqual(requests, 10)

            requests = self.planner._estimate_requests(
                ExploitationStrategy.BOOLEAN_BLIND
            )
            self.assertEqual(requests, 500)

    def test_estimate_duration(self):
        """Test duration estimation."""
        with patch.object(self.planner, "_has_tampers") as mock_has:
            mock_has.return_value = False
            duration = self.planner._estimate_duration(ExploitationStrategy.UNION)
            self.assertGreater(duration, 0)
            self.assertLess(duration, 60)

            duration = self.planner._estimate_duration(ExploitationStrategy.TIME_BLIND)
            self.assertGreater(duration, 100)

    def test_estimate_duration_cap(self):
        """Test duration estimation cap."""
        # Test with a strategy that would exceed the cap
        with patch.object(self.planner, "_has_tampers") as mock_has:
            mock_has.return_value = False
            duration = self.planner._estimate_duration(ExploitationStrategy.TIME_BLIND)
            self.assertLessEqual(duration, 3600)  # Cap at 1 hour

    def test_estimate_requests_with_tampers(self):
        """Test request estimation with tampers."""
        with patch.object(self.planner, "_has_tampers") as mock_has:
            mock_has.return_value = True

            requests = self.planner._estimate_requests(ExploitationStrategy.UNION)
            self.assertEqual(requests, 12)  # 10 * 1.2

    def test_calculate_risk_level(self):
        """Test risk level calculation."""
        risk = self.planner._calculate_risk_level(
            ExploitationStrategy.UNION, None, 95.0
        )
        self.assertEqual(risk, RiskLevel.LOW)

        risk = self.planner._calculate_risk_level(
            ExploitationStrategy.HYBRID, None, 50.0
        )
        self.assertEqual(risk, RiskLevel.HIGH)

    def test_calculate_risk_level_with_waf(self):
        """Test risk level calculation with WAF."""
        waf_result = Mock()
        waf_result.waf_detected = True
        waf_result.confidence = 80.0

        risk = self.planner._calculate_risk_level(
            ExploitationStrategy.BOOLEAN_BLIND, waf_result, 70.0
        )

        # WAF should increase risk
        self.assertIn(risk, [RiskLevel.HIGH, RiskLevel.CRITICAL])

    def test_score_union(self):
        """Test UNION strategy scoring."""
        sqli_result = Mock()
        sqli_result.union_injection_detected = True

        column_result = Mock()
        column_result.success = True
        column_result.column_count = 5
        column_result.reflective_columns = [1, 2]

        datatype_result = Mock()
        datatype_result.success = True

        score = self.planner._score_union(
            sqli_result, column_result, datatype_result, None
        )

        self.assertGreater(score, 80)

    def test_score_error_based(self):
        """Test Error-Based strategy scoring."""
        sqli_result = Mock()
        sqli_result.error_based_detected = True

        error_result = Mock()
        error_result.is_vulnerable = True
        error_result.extracted_values = ["test"]

        score = self.planner._score_error_based(sqli_result, error_result, None)

        self.assertGreater(score, 80)

    def test_score_boolean_blind(self):
        """Test Boolean Blind strategy scoring."""
        sqli_result = Mock()
        sqli_result.blind_injection_detected = True

        blind_result = Mock()
        blind_result.is_vulnerable = True
        blind_result.working_payloads = ["payload1"]

        score = self.planner._score_boolean_blind(sqli_result, blind_result, None)

        self.assertGreater(score, 80)

    def test_score_time_blind(self):
        """Test Time Blind strategy scoring."""
        sqli_result = Mock()
        sqli_result.time_based_detected = True

        time_result = Mock()
        time_result.is_vulnerable = True
        time_result.delay_seconds = 5

        score = self.planner._score_time_blind(sqli_result, time_result, None)

        self.assertGreater(score, 80)

    def test_score_oob(self):
        """Test OOB strategy scoring."""
        oob_result = Mock()
        oob_result.success = True
        oob_result.technique = OOBTechnique.DNS
        oob_result.confidence = 90.0
        oob_result.callbacks_received = 5

        scores = self.planner._score_oob(oob_result, None)

        self.assertGreater(scores[ExploitationStrategy.OOB_DNS], 80)
        self.assertEqual(scores[ExploitationStrategy.OOB_LDAP], 0)

    def test_score_hybrid(self):
        """Test Hybrid strategy scoring."""
        scores = {
            ExploitationStrategy.UNION: 90.0,
            ExploitationStrategy.ERROR_BASED: 80.0,
            ExploitationStrategy.BOOLEAN_BLIND: 70.0,
        }

        hybrid_score = self.planner._score_hybrid(scores)
        self.assertEqual(hybrid_score, 85.0)

    def test_apply_waf_penalties(self):
        """Test WAF penalty application."""
        scores = {
            ExploitationStrategy.UNION: 90.0,
            ExploitationStrategy.ERROR_BASED: 80.0,
        }

        waf_result = Mock()
        waf_result.waf_detected = True
        waf_result.confidence = 80.0

        penalized = self.planner._apply_waf_penalties(scores, waf_result)

        self.assertLess(penalized[ExploitationStrategy.UNION], 90.0)
        self.assertLess(penalized[ExploitationStrategy.ERROR_BASED], 80.0)

    def test_recommend_tampers(self):
        """Test tamper recommendations."""
        waf_result = Mock()
        waf_result.waf_detected = True
        waf_result.waf_name = "Cloudflare"

        tampers = self.planner._recommend_tampers(
            ExploitationStrategy.UNION, waf_result
        )

        self.assertIsInstance(tampers, list)
        self.assertGreater(len(tampers), 0)

    def test_recommend_tampers_no_waf(self):
        """Test tamper recommendations without WAF."""
        tampers = self.planner._recommend_tampers(
            ExploitationStrategy.BOOLEAN_BLIND, None
        )

        self.assertIsInstance(tampers, list)

    def test_build_reasoning(self):
        """Test reasoning building."""
        scores = {
            ExploitationStrategy.UNION: 90.0,
            ExploitationStrategy.ERROR_BASED: 80.0,
        }

        waf_result = Mock()
        waf_result.waf_detected = False

        reasoning = self.planner._build_reasoning(
            ExploitationStrategy.UNION, scores, waf_result, 95.0
        )

        self.assertIsInstance(reasoning, list)
        self.assertGreater(len(reasoning), 3)
        self.assertIn("Selected union with score", reasoning[0])

    def test_plan_attack_success(self):
        """Test successful attack planning."""
        sqli_result = Mock()
        sqli_result.union_injection_detected = True

        column_result = Mock()
        column_result.success = True
        column_result.column_count = 3
        column_result.reflective_columns = [1]

        datatype_result = Mock()
        datatype_result.success = True

        plan = self.planner.plan_attack(
            injection_point="id",
            sqli_result=sqli_result,
            column_result=column_result,
            datatype_result=datatype_result,
        )

        self.assertTrue(plan.success)
        self.assertEqual(plan.selected_strategy, ExploitationStrategy.UNION)
        self.assertGreater(plan.confidence, 70)

    def test_plan_attack_fallback(self):
        """Test attack planning with fallback selection."""
        sqli_result = Mock()
        sqli_result.error_based_detected = True

        error_result = Mock()
        error_result.is_vulnerable = True
        error_result.extracted_values = ["test"]

        plan = self.planner.plan_attack(
            injection_point="id",
            sqli_result=sqli_result,
            error_based_result=error_result,
        )

        self.assertTrue(plan.success)
        self.assertIsNotNone(plan.fallback_strategy)

    def test_plan_attack_no_strategies(self):
        """Test attack planning with no strategies available."""
        plan = self.planner.plan_attack(injection_point="id")

        self.assertFalse(plan.success)
        self.assertEqual(plan.selected_strategy, ExploitationStrategy.STOP)
        self.assertEqual(plan.confidence, 0.0)

    def test_plan_attack_with_waf(self):
        """Test attack planning with WAF detection."""
        waf_result = Mock()
        waf_result.waf_detected = True
        waf_result.confidence = 90.0
        waf_result.waf_name = "Cloudflare"

        plan = self.planner.plan_attack(injection_point="id", waf_result=waf_result)

        self.assertFalse(plan.success)
        reasoning_text = " ".join(plan.reasoning)
        self.assertIn("WAF detected", reasoning_text)

    def test_execute_plan_success(self):
        """Test successful plan execution."""
        plan = AttackPlanResult(
            success=True,
            selected_strategy=ExploitationStrategy.UNION,
            execution_order=[ExploitationStrategy.UNION],
            confidence=90.0,
        )

        def execution_function(strategy, **kwargs):
            return {"success": True, "data": "test_data"}

        results = self.planner.execute_plan(plan, execution_function)

        self.assertTrue(results["success"])
        self.assertEqual(results["strategy_used"], ExploitationStrategy.UNION)
        self.assertEqual(results["data"], "test_data")

    def test_execute_plan_failure_then_success(self):
        """Test plan execution with failure then success."""
        plan = AttackPlanResult(
            success=True,
            selected_strategy=ExploitationStrategy.UNION,
            fallback_strategy=ExploitationStrategy.ERROR_BASED,
            execution_order=[
                ExploitationStrategy.UNION,
                ExploitationStrategy.ERROR_BASED,
            ],
            confidence=90.0,
        )

        call_count = 0

        def execution_function(strategy, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"success": False, "error": "Failed"}
            return {"success": True, "data": "fallback_data"}

        results = self.planner.execute_plan(plan, execution_function)

        self.assertTrue(results["success"])
        self.assertEqual(results["strategy_used"], ExploitationStrategy.ERROR_BASED)
        self.assertEqual(results["data"], "fallback_data")

    def test_execute_plan_all_fail(self):
        """Test plan execution with all strategies failing."""
        plan = AttackPlanResult(
            success=True,
            selected_strategy=ExploitationStrategy.UNION,
            fallback_strategy=ExploitationStrategy.ERROR_BASED,
            execution_order=[
                ExploitationStrategy.UNION,
                ExploitationStrategy.ERROR_BASED,
            ],
            confidence=90.0,
        )

        def execution_function(strategy, **kwargs):
            return {"success": False, "error": "Failed"}

        results = self.planner.execute_plan(plan, execution_function)

        self.assertFalse(results["success"])
        self.assertEqual(len(results["attempts"]), 2)

    def test_execute_plan_invalid(self):
        """Test execution with invalid plan."""
        plan = AttackPlanResult(success=False)

        def execution_function(strategy, **kwargs):
            return {"success": True}

        results = self.planner.execute_plan(plan, execution_function)

        self.assertFalse(results["success"])
        self.assertIn("Invalid plan", results["errors"][0])

    def test_auto_exploit_success(self):
        """Test automatic exploitation success."""
        detection_results = {}

        def execution_function(strategy, **kwargs):
            return {"success": True, "data": "auto_data"}

        with patch.object(self.planner, "plan_attack") as mock_plan:
            plan = AttackPlanResult(
                success=True,
                selected_strategy=ExploitationStrategy.UNION,
                execution_order=[ExploitationStrategy.UNION],
                confidence=90.0,
            )
            mock_plan.return_value = plan

            results = self.planner.auto_exploit(
                "id", execution_function, detection_results
            )

            self.assertTrue(results["success"])
            self.assertIn("plan", results)

    def test_auto_exploit_no_plan(self):
        """Test automatic exploitation with no plan."""
        detection_results = {}

        def execution_function(strategy, **kwargs):
            return {"success": True}

        with patch.object(self.planner, "plan_attack") as mock_plan:
            plan = AttackPlanResult(success=False)
            mock_plan.return_value = plan

            results = self.planner.auto_exploit(
                "id", execution_function, detection_results
            )

            self.assertFalse(results["success"])
            self.assertIn("No viable exploitation strategy found", results["error"])

    def test_validate_plan_valid(self):
        """Test validating a valid plan."""
        plan = AttackPlanResult(
            success=True, selected_strategy=ExploitationStrategy.UNION, confidence=85.0
        )

        self.assertTrue(self.planner.validate_plan(plan))

    def test_validate_plan_invalid(self):
        """Test validating an invalid plan."""
        plan = AttackPlanResult(
            success=False, selected_strategy=ExploitationStrategy.STOP, confidence=50.0
        )

        self.assertFalse(self.planner.validate_plan(plan))

    def test_validate_plan_low_confidence(self):
        """Test validating a plan with low confidence."""
        plan = AttackPlanResult(
            success=True,
            selected_strategy=ExploitationStrategy.UNION,
            confidence=50.0,  # Below threshold of 70
        )

        self.assertFalse(self.planner.validate_plan(plan))

    def test_strategy_scores_priority(self):
        """Test strategy priority scoring."""
        self.assertGreater(
            self.planner.get_strategy_score(ExploitationStrategy.UNION),
            self.planner.get_strategy_score(ExploitationStrategy.TIME_BLIND),
        )


class TestAttackPlannerEdgeCases(unittest.TestCase):
    """Test edge cases for Attack Planner."""

    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.planner = AttackPlanner()

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_plan_with_empty_results(self):
        """Test planning with empty detection results."""
        plan = self.planner.plan_attack("id")
        self.assertFalse(plan.success)
        self.assertEqual(plan.selected_strategy, ExploitationStrategy.STOP)

    def test_plan_with_partial_results(self):
        """Test planning with partial results."""
        sqli_result = Mock()
        sqli_result.union_injection_detected = True

        plan = self.planner.plan_attack(injection_point="id", sqli_result=sqli_result)

        self.assertTrue(plan.success)

    def test_execute_plan_with_exception(self):
        """Test plan execution with exception."""
        plan = AttackPlanResult(
            success=True,
            selected_strategy=ExploitationStrategy.UNION,
            execution_order=[ExploitationStrategy.UNION],
            confidence=90.0,
        )

        def execution_function(strategy, **kwargs):
            raise ValueError("Test exception")

        results = self.planner.execute_plan(plan, execution_function)

        self.assertFalse(results["success"])
        self.assertIn("Test exception", str(results["errors"]))

    def test_auto_exploit_with_plan_validation(self):
        """Test auto exploit with plan validation."""
        detection_results = {}

        def execution_function(strategy, **kwargs):
            return {"success": True, "data": "test"}

        with patch.object(self.planner, "plan_attack") as mock_plan:
            plan = AttackPlanResult(
                success=True,
                selected_strategy=ExploitationStrategy.UNION,
                confidence=60.0,
                execution_order=[ExploitationStrategy.UNION],
            )
            mock_plan.return_value = plan

            results = self.planner.auto_exploit(
                "id", execution_function, detection_results
            )

            self.assertTrue(results["success"])


if __name__ == "__main__":
    unittest.main()
