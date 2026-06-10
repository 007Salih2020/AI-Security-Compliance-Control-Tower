from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:8].upper()}"


class ComplianceControl(BaseModel):
    framework: str
    control_id: str
    control_name: str
    control_description: str
    evidence_required: List[str] = Field(default_factory=list)
    risk_domain: str
    remediation_expectation: str
    keywords: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)
    finding_categories: List[str] = Field(default_factory=list)
    model_triggers: List[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    risk_score: int = 0
    risk_rating: Literal["Low", "Medium", "High", "Critical"] = "Low"
    risk_reasoning: str = ""
    business_impact: str = ""


class AIAnalysis(BaseModel):
    analysis_id: str = Field(default_factory=lambda: new_id("ANL"))
    target_id: str
    target_type: Literal["finding", "model"]
    technical_explanation: str
    business_impact: str
    compliance_impact: str
    likelihood_reasoning: str
    severity_reasoning: str
    remediation_plan: List[str]
    executive_summary: str
    audit_evidence_summary: str
    suggested_owner: str
    suggested_priority: str
    trusted: bool = False
    generated_by: str = "local_mock"
    timestamp: str = Field(default_factory=utcnow_iso)


class EvaluationResult(BaseModel):
    eval_id: str = Field(default_factory=lambda: new_id("EVAL"))
    target_id: str
    target_type: Literal["finding", "model", "evidence", "remediation"]
    metric: str
    score: float
    pass_fail: bool
    comment: str
    evaluator: str
    timestamp: str = Field(default_factory=utcnow_iso)


class GovernanceDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: new_id("GOV"))
    action: str
    decision: Literal["allow", "deny", "require_approval"]
    matched_rule: str
    reason: str
    policy_name: str
    timestamp: str = Field(default_factory=utcnow_iso)
    context: Dict[str, Any] = Field(default_factory=dict)


class EvidenceMetadata(BaseModel):
    evidence_id: str = Field(default_factory=lambda: new_id("EVID"))
    target_id: str
    target_type: Literal["finding", "model", "executive_summary"]
    json_path: Optional[str] = None
    markdown_path: Optional[str] = None
    sha256: str
    created_at: str = Field(default_factory=utcnow_iso)
    summary: str


class NormalizedFinding(BaseModel):
    finding_id: str
    title: str
    description: str
    provider: str
    service: str
    resource_id: str
    resource_name: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    status: str
    category: str
    source_tool: str
    compliance_frameworks: List[str] = Field(default_factory=list)
    control_ids: List[str] = Field(default_factory=list)
    remediation: str
    evidence_references: List[str] = Field(default_factory=list)
    created_at: str
    asset_criticality: Literal["low", "medium", "high", "critical"] = "medium"
    internet_exposure: bool = False
    compliance_relevance: Literal["low", "medium", "high"] = "medium"
    exploitability: Literal["low", "medium", "high"] = "medium"
    data_sensitivity: Literal["public", "internal", "confidential", "regulated"] = "internal"
    ai_agent_involved: bool = False
    remediation_status: Literal["open", "planned", "in_progress", "mitigated"] = "open"
    risk_score: int = 0
    risk_rating: Literal["Low", "Medium", "High", "Critical"] = "Low"
    risk_reasoning: str = ""
    business_impact: str = ""
    mapped_controls: List[ComplianceControl] = Field(default_factory=list)
    ai_analysis: Optional[AIAnalysis] = None
    evaluations: List[EvaluationResult] = Field(default_factory=list)
    evidence_id: Optional[str] = None
    trusted_analysis: bool = False
    last_updated: str = Field(default_factory=utcnow_iso)


class ModelInventoryRecord(BaseModel):
    model_inventory_id: str
    model_name: str
    deployment_name: str
    provider: str
    platform: str
    subscription_id: str
    resource_group: str
    region: str
    endpoint: str
    model_family: str
    model_version: str
    deployment_type: str
    environment: str
    owner: str
    business_unit: str
    application_name: str
    use_case: str
    data_classification: str
    processes_personal_data: bool
    processes_confidential_data: bool
    internet_accessible: bool
    private_network_enabled: bool
    logging_enabled: bool
    content_filtering_enabled: bool
    evaluation_available: bool
    red_team_tested: bool
    used_by_agent: bool
    approval_status: Literal["approved", "pending", "needs_review", "rejected"]
    risk_tier: Literal["Low", "Medium", "High", "Critical"] = "Low"
    risk_score: int = 0
    risk_reasoning: str = ""
    recommended_actions: List[str] = Field(default_factory=list)
    discovered_at: str
    last_seen: str
    source: str
    tags: Dict[str, Any] = Field(default_factory=dict)
    compliance_mappings: List[ComplianceControl] = Field(default_factory=list)
    evidence_id: Optional[str] = None
    missing_fields: List[str] = Field(default_factory=list)
    governance_review_required: bool = False
    public_endpoint: bool = False
    ai_analysis: Optional[AIAnalysis] = None
    evaluations: List[EvaluationResult] = Field(default_factory=list)
    trusted_analysis: bool = False


class OwnerUpdateRequest(BaseModel):
    owner: str
    business_unit: str
    use_case: str


class PolicyCheckRequest(BaseModel):
    action: str
    context: Dict[str, Any] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    file: str


class SecuritySyncRequest(BaseModel):
    lookback_hours: int = 24
    include_policy_states: bool = True
    include_activity_log: bool = True
    include_prowler: bool = True
    include_github_artifacts: bool = True
    replace_existing: bool = True
    preserve_ai_governance: bool = True
    generate_evidence: bool = True
    evidence_limit: int = 25


class SecuritySyncSummary(BaseModel):
    sync_id: str = Field(default_factory=lambda: new_id("SYNC"))
    findings_ingested: int
    source_counts: Dict[str, int] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    replaced_existing: bool = True
    preserved_categories: List[str] = Field(default_factory=list)
    mode: str = "demo"
    synced_at: str = Field(default_factory=utcnow_iso)


class AppState(BaseModel):
    findings: Dict[str, NormalizedFinding] = Field(default_factory=dict)
    models: Dict[str, ModelInventoryRecord] = Field(default_factory=dict)
    governance_decisions: List[GovernanceDecision] = Field(default_factory=list)
    reports: List[EvidenceMetadata] = Field(default_factory=list)
    last_reset: str = Field(default_factory=utcnow_iso)


class DemoSummary(BaseModel):
    findings_ingested: int
    models_discovered: int
    models_missing_owners: int
    high_risk_models: int
    critical_findings: int
    controls_mapped: int
    analyses_generated: int
    model_risk_assessments_generated: int
    evaluations_passed: str
    governance_denials: int
    evidence_reports_generated: int
    ciso_message: str
