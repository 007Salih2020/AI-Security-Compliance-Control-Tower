from __future__ import annotations

from typing import List

from app.models import EvaluationResult

try:
    import braintrust  # type: ignore  # pragma: no cover
except ImportError:  # pragma: no cover
    braintrust = None


def braintrust_available() -> bool:
    return braintrust is not None


def run_braintrust_checks(*_args, **_kwargs) -> List[EvaluationResult]:
    return []
