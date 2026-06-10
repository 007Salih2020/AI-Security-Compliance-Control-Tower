from __future__ import annotations

from typing import Any, Dict

from governance.policy_engine import evaluate_action


def check_action(action: str, context: Dict[str, Any] | None = None):
    return evaluate_action(action=action, context=context or {})
