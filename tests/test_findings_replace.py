from __future__ import annotations

from app.database import get_db
from app.models import NormalizedFinding


def test_replace_findings_preserves_ai_governance_category():
    db = get_db()
    existing = [
        NormalizedFinding(
            finding_id="OLD-001",
            title="Old cloud finding",
            description="Old finding to be replaced",
            provider="Azure",
            service="Storage",
            resource_id="resource-1",
            resource_name="resource-1",
            severity="High",
            status="open",
            category="Cloud Security Posture",
            source_tool="Azure Policy",
            remediation="Fix it",
            evidence_references=[],
            created_at="2026-06-05T00:00:00Z",
        ),
        NormalizedFinding(
            finding_id="AI-AGENT-001",
            title="AI agent attempted destructive cloud action",
            description="Agent attempted a destructive action.",
            provider="Internal AI",
            service="AI Agent Runtime",
            resource_id="resource-2",
            resource_name="agent-1",
            severity="Critical",
            status="open",
            category="AI Governance",
            source_tool="Agent Trace",
            remediation="Require approval.",
            evidence_references=[],
            created_at="2026-06-05T00:00:00Z",
        ),
    ]
    db.save_findings(existing)

    replacement = [
        NormalizedFinding(
            finding_id="NEW-001",
            title="New live finding",
            description="Live finding",
            provider="Azure",
            service="Key Vault",
            resource_id="resource-3",
            resource_name="kv-1",
            severity="High",
            status="open",
            category="Cloud Compliance",
            source_tool="Azure Policy",
            remediation="Enable the control.",
            evidence_references=[],
            created_at="2026-06-05T01:00:00Z",
        )
    ]

    db.replace_findings(replacement, preserve_categories=["AI Governance"])
    findings = {finding.finding_id for finding in db.get_findings()}

    assert findings == {"NEW-001", "AI-AGENT-001"}

