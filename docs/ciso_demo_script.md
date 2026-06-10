# ControlLens AI CISO Demo Script

## 30-Second Opening Pitch

ControlLens AI gives security and compliance leaders a single control tower for cloud findings, AI/LLM deployments, model ownership, AI-agent governance, and audit evidence. Instead of showing one more scanner output, it shows which risks matter, which controls they map to, who owns them, and whether the organization could defend its AI use in an audit tomorrow.

## 3-Minute Walkthrough

1. Start on the Executive Overview dashboard page.
2. State the topline numbers: findings, high-risk models, missing owners, governance denials, evidence generated.
3. Open the Security Findings page and highlight `AZURE-003` to show the logging gap.
4. Open the AI / LLM Inventory page and point to `MODEL-001` with missing owner, missing approval, and missing logging.
5. Open Governance Decisions and show that `delete_resource` was denied while `approve_model` requires human approval.
6. Open Evidence Reports and show a hash-backed markdown report.

## 5-Minute Detailed Demo Flow

1. Run `python cli.py demo`.
2. Say that all inputs are local sample data to keep the walkthrough credential-free and repeatable.
3. Show `AZURE-003` and explain that it maps directly to ISO 27001 A.12.4 Logging.
4. Show `AI-AGENT-001` and explain how the policy engine blocks destructive AI-agent actions.
5. Show `MODEL-001` and explain how missing ownership and approval become measurable governance risk.
6. Show the compliance coverage page and point to ISO 27001, NIST 800-53, DORA, CIS, and AI governance controls.
7. Open `reports/model_evidence_MODEL-001.md` and show the owner gap, risk score, mapped controls, and recommended actions.
8. Close on the executive summary and explain that the same platform can later be connected to live Azure discovery and Azure OpenAI analysis.

## Likely CISO Questions

### How does this reduce audit effort?

It creates structured evidence packages directly from operational data, including hashes, timestamps, control mappings, governance decisions, and remediation context. That replaces manual screenshot collection and fragmented control narratives.

### How does this improve AI governance?

It inventories AI systems, scores model risk, highlights missing owners and approvals, verifies logging and evaluation evidence, and blocks risky agent actions through deterministic policies.

### How does this support DevSecOps?

It ingests SARIF and SBOM-style findings, supports CLI and GitHub Actions automation, and turns pipeline findings into compliance-mapped evidence.

### Can this expand to real Azure?

Yes. The architecture already includes an Azure discovery abstraction and an Azure OpenAI wrapper. The current MVP uses local-safe fallback behavior until tenant-specific integration is configured.

## Strong Answers

- This is not another scanner dashboard; it is a control mapping and evidence engine.
- The AI story is governed, not assumed safe.
- The platform is useful even before live Azure integration because governance, scoring, policy enforcement, and evidence generation are already functional.

## Business Value

- Reduced time to build audit evidence.
- Better prioritization of cloud and AI risks.
- Clear owner accountability for AI systems.
- Safer AI-agent adoption with deterministic guardrails.

## Roadmap

- Live Azure Resource Graph and Azure ML discovery.
- Approval workflows backed by tickets or GRC systems.
- Immutable evidence storage in Azure.
- Expanded AI evaluation datasets and red-team workflows.

## How This Reduces Audit Effort

The platform captures evidence once and reuses it across findings, AI models, and executive reporting. That changes the audit model from manual evidence gathering to continuously generated artifacts.

## How This Improves AI Governance

It operationalizes AI policy through owner assignment, approval status, logging requirements, evaluation evidence, and policy-checked agent actions.

## How This Supports DevSecOps

It brings findings from code, dependencies, and cloud posture into one normalized data model and one CLI-first automation surface.

## How This Can Expand To Real Azure Environments

Replace local sample discovery with Azure Resource Graph, Azure Machine Learning, and Azure OpenAI discovery adapters; move JSON persistence to a managed database; route evidence to durable storage; integrate with Entra ID and Managed Identity.
