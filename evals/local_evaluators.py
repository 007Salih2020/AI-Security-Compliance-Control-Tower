from __future__ import annotations

from typing import List

from app.models import AIAnalysis, EvaluationResult, ModelInventoryRecord, NormalizedFinding


def evaluate_finding_analysis(finding: NormalizedFinding) -> List[EvaluationResult]:
    if finding.ai_analysis is None:
        return []
    results = _evaluate_target(
        target_id=finding.finding_id,
        target_type="finding",
        analysis=finding.ai_analysis,
        reference_text=" ".join([finding.title, finding.description, finding.remediation]),
        fail_for_mock_secret=(
            "secret detected" in finding.title.lower()
            or finding.category.lower() == "secrets exposure"
        ),
    )
    finding.evaluations = results
    finding.trusted_analysis = all(result.pass_fail for result in results)
    return results


def evaluate_model_analysis(model: ModelInventoryRecord) -> List[EvaluationResult]:
    if model.ai_analysis is None:
        return []
    results = _evaluate_target(
        target_id=model.model_inventory_id,
        target_type="model",
        analysis=model.ai_analysis,
        reference_text=" ".join([model.model_name, model.application_name, model.use_case, model.risk_reasoning]),
        fail_for_mock_secret=False,
    )
    model.evaluations = results
    model.trusted_analysis = all(result.pass_fail for result in results)
    return results


def _evaluate_target(
    target_id: str,
    target_type: str,
    analysis: AIAnalysis,
    reference_text: str,
    fail_for_mock_secret: bool,
) -> List[EvaluationResult]:
    metrics: List[EvaluationResult] = []
    combined_text = " ".join(
        [
            analysis.technical_explanation,
            analysis.business_impact,
            analysis.compliance_impact,
            analysis.executive_summary,
            " ".join(analysis.remediation_plan),
        ]
    ).lower()

    def add(metric: str, score: float, comment: str, threshold: float = 0.7) -> None:
        metrics.append(
            EvaluationResult(
                target_id=target_id,
                target_type=target_type,  # type: ignore[arg-type]
                metric=metric,
                score=round(score, 2),
                pass_fail=score >= threshold,
                comment=comment,
                evaluator="local_heuristic",
            )
        )

    grounded_score = 0.9 if any(word in combined_text for word in reference_text.lower().split()[:6]) else 0.55
    factuality_score = 0.85 if len(analysis.technical_explanation.split()) >= 10 else 0.6
    hallucination_score = 0.45 if fail_for_mock_secret and analysis.generated_by == "local_mock" else 0.88
    pii_leakage_score = 0.95 if "password" not in combined_text and "api key" not in combined_text else 0.4
    security_relevance_score = 0.92 if any(word in combined_text for word in ["risk", "control", "audit", "owner"]) else 0.6
    completeness_score = 0.9 if len(analysis.remediation_plan) >= 2 else 0.5
    executive_clarity_score = 0.85 if len(analysis.executive_summary.split()) >= 8 else 0.6
    usefulness_score = 0.9 if any("enable" in step.lower() or "assign" in step.lower() for step in analysis.remediation_plan) else 0.65

    add("factuality", factuality_score, "Checks whether the analysis is sufficiently concrete.")
    add("groundedness", grounded_score, "Checks whether analysis language overlaps with the source record.")
    add("hallucination_risk", hallucination_score, "Lower score indicates the mock analysis needs human review.")
    add("pii_leakage", pii_leakage_score, "Checks that no obvious sensitive secrets are repeated in the narrative.")
    add("security_relevance", security_relevance_score, "Checks that the narrative discusses risk and controls.")
    add("completeness", completeness_score, "Checks that remediation guidance is actionable.")
    add("executive_clarity", executive_clarity_score, "Checks that the executive summary is understandable.")
    add("remediation_usefulness", usefulness_score, "Checks that remediation includes concrete next steps.")
    return metrics
