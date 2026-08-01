"""
Attack Planning Helpers
Phase 20
"""


class OracleAttackHelper:
    """Attack planning helper functions."""


def plan_attack_impl(oracle_enum, *args, **kwargs):
    return oracle_enum._attack_planner.plan_attack(*args, **kwargs)


def execute_plan_impl(oracle_enum, *args, **kwargs):
    return oracle_enum._attack_planner.execute_plan(*args, **kwargs)
