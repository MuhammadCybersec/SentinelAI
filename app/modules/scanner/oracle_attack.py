"""
Attack Planning Helpers
Phase 20
"""

import logging
from typing import Any, Dict, Optional

from .attack_planner import (
    AttackPlanner,
    AttackPlanResult,
    ExploitationStrategy,
    RiskLevel,
)


class OracleAttackHelper:
    """Attack planning helper functions."""

    pass


def plan_attack_impl(oracle_enum, *args, **kwargs):
    return oracle_enum._attack_planner.plan_attack(*args, **kwargs)


def execute_plan_impl(oracle_enum, *args, **kwargs):
    return oracle_enum._attack_planner.execute_plan(*args, **kwargs)
