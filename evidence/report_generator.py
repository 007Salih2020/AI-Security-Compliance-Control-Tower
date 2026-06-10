from __future__ import annotations

from jinja2 import Template

FINDING_TEMPLATE = Template(
    """# Finding Evidence: {{ finding.finding_id }}

## Summary
- Title: {{ finding.title }}
- Severity: {{ finding.severity }}
- Risk Rating: {{ finding.risk_rating }} ({{ finding.risk_score }})
- Resource: {{ finding.resource_name }}
- Source: {{ finding.source_tool }}
- Evidence ID: {{ evidence_id }}
- Hash: {{ sha256 }}

## Description
{{ finding.description }}

## Compliance Controls
{% for control in finding.mapped_controls -%}
- {{ control.framework }} {{ control.control_id }}: {{ control.control_name }}
{% endfor %}

## AI Analysis
- Technical Explanation: {{ analysis.technical_explanation }}
- Business Impact: {{ analysis.business_impact }}
- Compliance Impact: {{ analysis.compliance_impact }}
- Executive Summary: {{ analysis.executive_summary }}

## Evaluation Results
{% for evaluation in evaluations -%}
- {{ evaluation.metric }}: {{ evaluation.score }} ({{ "PASS" if evaluation.pass_fail else "FAIL" }}) - {{ evaluation.comment }}
{% endfor %}

## Governance Decisions
{% for decision in governance_decisions -%}
- {{ decision.action }} => {{ decision.decision }} via {{ decision.matched_rule }}: {{ decision.reason }}
{% endfor %}

## Remediation Recommendation
{{ finding.remediation }}
"""
)

MODEL_TEMPLATE = Template(
    """# Model Governance Evidence: {{ model.model_inventory_id }}

## Summary
- Model: {{ model.model_name }}
- Deployment: {{ model.deployment_name }}
- Risk Tier: {{ model.risk_tier }} ({{ model.risk_score }})
- Owner: {{ model.owner }}
- Approval Status: {{ model.approval_status }}
- Evidence ID: {{ evidence_id }}
- Hash: {{ sha256 }}

## Model Context
- Application: {{ model.application_name }}
- Use Case: {{ model.use_case }}
- Data Classification: {{ model.data_classification }}
- Personal Data: {{ model.processes_personal_data }}
- Confidential Data: {{ model.processes_confidential_data }}
- Logging Enabled: {{ model.logging_enabled }}
- Content Filtering Enabled: {{ model.content_filtering_enabled }}

## Compliance Controls
{% for control in model.compliance_mappings -%}
- {{ control.framework }} {{ control.control_id }}: {{ control.control_name }}
{% endfor %}

## AI Risk Analysis
- Technical Explanation: {{ analysis.technical_explanation }}
- Business Impact: {{ analysis.business_impact }}
- Compliance Impact: {{ analysis.compliance_impact }}
- Executive Summary: {{ analysis.executive_summary }}

## Evaluation Results
{% for evaluation in evaluations -%}
- {{ evaluation.metric }}: {{ evaluation.score }} ({{ "PASS" if evaluation.pass_fail else "FAIL" }}) - {{ evaluation.comment }}
{% endfor %}

## Recommended Actions
{% for action in model.recommended_actions -%}
- {{ action }}
{% endfor %}
"""
)


def render_finding_markdown(**context) -> str:
    return FINDING_TEMPLATE.render(**context)


def render_model_markdown(**context) -> str:
    return MODEL_TEMPLATE.render(**context)
