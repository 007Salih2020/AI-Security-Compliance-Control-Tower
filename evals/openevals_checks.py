from __future__ import annotations

from typing import List

from app.models import EvaluationResult

try:
    import langchain  # type: ignore  # pragma: no cover
except ImportError:  # pragma: no cover
    langchain = None


def openevals_available() -> bool:
    return langchain is not None


def run_openevals_checks(*_args, **_kwargs) -> List[EvaluationResult]:
    return []
