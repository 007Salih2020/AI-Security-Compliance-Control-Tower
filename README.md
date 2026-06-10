# ControlLens AI

ControlLens AI is an AI Security & Compliance Control Tower that discovers cloud and AI/LLM risks, registers model ownership, maps findings to compliance controls, evaluates AI-generated remediation, enforces AI-agent governance, and produces audit-ready evidence for CISOs.

## Business Value

Security, compliance, and AI governance data usually lives in separate tools. ControlLens AI turns fragmented cloud findings, DevSecOps alerts, AI deployment metadata, and agent actions into one CISO-facing control plane with evidence, risk scoring, and governance decisions.

## CISO Value Proposition

- One inventory for cloud findings and AI/LLM deployments.
- Immediate visibility into missing AI ownership, logging gaps, approval gaps, and internet-exposed deployments.
- Deterministic governance checks for AI-agent actions.
- Audit-ready evidence packages and executive summaries generated from the same source data.

## Architecture

```text
Sample Findings / AI Inventory / Agent Traces
            |
            v
   Ingestion + Normalization
            |
            v
 Risk Scoring + Control Mapping
            |
            +----------------------+
            |                      |
            v                      v
   AI Risk Analysis         Governance Policy Engine
            |                      |
            +----------+-----------+
                       |
                       v
           Evaluation + Evidence Builder
                       |
         +-------------+-------------+
         |                           |
         v                           v
   FastAPI API                  Streamlit UI
         |                           |
         +-------------+-------------+
                       |
                       v
              Reports / Executive Summary
```

## Features

- Finding ingestion for Prowler-style Azure findings, SARIF, SBOM, and risky AI-agent traces.
- Live security sync for Azure Policy, Azure Activity Log, optional native Prowler outputs, and optional GitHub SARIF/SBOM artifacts.
- Common normalized schema for security findings.
- YAML-based compliance control mapper for ISO 27001, NIST 800-53, DORA, CIS Controls, SOC 2 placeholders, and AI governance controls.
- AI / LLM Inventory & Model Risk Registry with owner enrichment and governance scoring.
- Deterministic Azure OpenAI fallback analysis for local demos.
- Heuristic LLM evaluation layer with room for Braintrust and OpenEvals integration later.
- AI-agent policy engine with allow, deny, and require-approval decisions.
- Audit evidence generation in JSON and Markdown with hashes.
- FastAPI backend, Typer CLI, Streamlit dashboard, Docker runtime, and GitHub Actions workflow.

## AI / LLM Inventory & Model Risk Registry

The registry answers the CISO question: where are our AI models deployed, who owns them, what data do they touch, and what governance risk do they create?

Each model record captures:

- ownership and business unit
- deployment location and platform
- approval status
- logging and content filtering status
- evaluation and red-team evidence status
- data classification
- agent usage
- risk score, risk tier, and recommended actions

## Tech Stack

- Python 3.11
- FastAPI
- Typer
- Streamlit
- Pydantic
- JSON persistence for local demo mode
- PyYAML
- Rich
- Pandas
- Jinja2
- Pytest
- OpenAI Python SDK with Azure wrapper and local fallback

## Folder Structure

```text
app/                  FastAPI app, config, models, persistence, routes, shared services
scanners/             Adapters for findings ingestion and normalization
models_inventory/     AI/LLM discovery, registry, owner enrichment, model risk scoring
ai/                   Analysis generation, prompts, remediation, executive summary
compliance/           YAML control catalogs and control mapping engine
governance/           AI-agent policy rules and policy engine
evals/                Local evaluation heuristics and optional integration wrappers
evidence/             Evidence report generation and hashing
risk/                 Security finding risk scoring
dashboard/            Streamlit dashboard
samples/              Local demo datasets
reports/              Generated evidence packages
docs/                 Demo script for executive walkthroughs
tests/                Pytest coverage for core flows
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python cli.py demo
```

## One-Click Startup

```bash
./start.sh
./start.sh 8601
```

`start.sh` creates the virtual environment if needed, clears Python and Streamlit caches, frees the target port, installs dependencies, and launches the Streamlit app from `ui.py`.

## Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `APP_NAME` | Application name | `ControlLens AI` |
| `APP_ENV` | Runtime environment | `local` |
| `DEMO_MODE` | Local deterministic demo mode | `true` |
| `DATA_STORE_PATH` | JSON persistence file | `data/store.json` |
| `REPORTS_DIR` | Evidence output folder | `reports` |
| `SAMPLES_DIR` | Local sample data folder | `samples` |
| `ENABLE_AZURE_DISCOVERY` | Enables live Azure model discovery for background/default flows | `false` |
| `AZURE_TENANT_ID` | Service principal tenant for Azure auth | empty |
| `AZURE_CLIENT_ID` | Service principal client ID for Azure auth | empty |
| `AZURE_CLIENT_SECRET` | Service principal secret for Azure auth | empty |
| `AZURE_SUBSCRIPTION_ID` | Azure discovery scope; comma-separated subscriptions supported | empty |
| `AZURE_AUTH_MODE` | Azure credential mode: `auto`, `env`, `cli`, `managed_identity`, or `default` | `auto` |
| `AZURE_ACTIVITY_LOG_LOOKBACK_HOURS` | Lookback window for live Azure Activity Log findings | `24` |
| `AZURE_POLICY_QUERY_LIMIT` | Max Azure Policy non-compliance rows per subscription sync | `200` |
| `AZURE_OPENAI_ENDPOINT` | Optional Azure OpenAI endpoint | empty |
| `AZURE_OPENAI_API_KEY` | Optional Azure OpenAI API key | empty |
| `AZURE_OPENAI_KEY` | Alias supported for Azure OpenAI API key | empty |
| `AZURE_OPENAI_DEPLOYMENT` | Optional Azure OpenAI deployment name | empty |
| `AZURE_OPENAI_API_VERSION` | Azure OpenAI API version | `2024-02-01` |
| `PROWLER_OUTPUT_DIR` | Directory where native Prowler JSON/CSV outputs are stored | `data/prowler-output` |
| `PROWLER_OUTPUT_FILENAME_PREFIX` | Prefix used for Prowler output discovery | `controllens-azure-security` |
| `PROWLER_BINARY` | Local Prowler CLI binary name or path | `prowler` |
| `ENABLE_LOCAL_PROWLER_EXECUTION` | Run a local Prowler CLI before ingesting native output | `false` |
| `GITHUB_TOKEN` | Optional token for GitHub Actions artifact download | empty |
| `GITHUB_REPOSITORY` | Repo in `owner/name` format for artifact download | empty |
| `GITHUB_API_URL` | GitHub API base URL | `https://api.github.com` |
| `GITHUB_ARTIFACTS_DIR` | Local folder for SARIF/SBOM artifact ingestion | `data/github-artifacts` |
| `GITHUB_ARTIFACT_NAMES` | Comma-separated artifact name filters | `sarif,sbom,security,codeql` |
| `GITHUB_ARTIFACT_LIMIT` | Max matching GitHub artifacts downloaded per sync | `3` |
| `UI_PORT` | Default Streamlit port | `8503` |
| `API_PORT` | Default FastAPI port | `8000` |

## Demo Commands

```bash
python cli.py demo
python cli.py init-demo
python cli.py ingest --file samples/prowler_azure_findings.json
python cli.py analyze --finding-id AZURE-001
python cli.py evaluate --finding-id AZURE-001
python cli.py evidence --finding-id AZURE-001
python cli.py discover-models --source local
python cli.py discover-models --source azure
python cli.py sync-security
python cli.py sync-security --lookback-hours 12 --no-include-github-artifacts
python cli.py models list
python cli.py models risk
python cli.py models evidence --model-id MODEL-001
python cli.py model-owner set --model-id MODEL-001 --owner "Security AI Team" --business-unit "Cybersecurity" --use-case "Security finding triage"
python cli.py policy-check --action delete_resource
python cli.py executive-summary
```

## API Usage

Run the API:

```bash
uvicorn app.main:app --reload
```

Key endpoints:

- `GET /health`
- `GET /reports`
- `GET /findings`
- `GET /findings/{finding_id}`
- `POST /ingest`
- `POST /analyze/{finding_id}`
- `POST /evaluate/{finding_id}`
- `POST /evidence/{finding_id}`
- `POST /sync/security/azure`
- `GET /models`
- `GET /models/unknown-owners`
- `GET /models/high-risk`
- `POST /models/discover`
- `POST /models/{model_id}/owner`
- `POST /models/{model_id}/risk`
- `POST /models/{model_id}/evaluate`
- `POST /models/{model_id}/evidence`
- `POST /policy/check`

Example:

```bash
curl -X POST http://127.0.0.1:8000/models/discover
curl -X POST "http://127.0.0.1:8000/models/discover?source=azure"
curl -X POST http://127.0.0.1:8000/sync/security/azure
curl -X POST http://127.0.0.1:8000/policy/check \
  -H "Content-Type: application/json" \
  -d '{"action":"delete_resource","context":{"environment":"production"}}'
```

## Dashboard Usage

```bash
streamlit run ui.py
```

For live Azure inventory, either:

```bash
az login
az account set --subscription "<your-subscription-id>"
python cli.py discover-models --source azure
```

or set the service principal values in `.env`:

```bash
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
AZURE_SUBSCRIPTION_ID=...
```

If both the service principal and Azure CLI are available, the default `AZURE_AUTH_MODE=auto`
tries the service principal first and falls back to your `az login` identity if the service
principal authenticates but does not have enough authorization.

For live security findings, the dashboard and CLI sync path combine:

- Azure Policy non-compliance states
- Azure Activity Log risky control-plane operations
- native Prowler JSON/CSV outputs from `data/prowler-output`
- optional GitHub SARIF/SBOM artifacts from `data/github-artifacts` or the GitHub API

To run the optional native Prowler container and write fresh output locally:

```bash
docker compose --profile live-security up prowler-runner
python cli.py sync-security
```

Pages:

- Executive Overview
- Security Findings
- Compliance Coverage
- AI / LLM Inventory
- Model Risk Registry
- Governance Decisions
- Evidence Reports

## Security Design

- No secrets are committed.
- Environment-based configuration only.
- Graceful local fallback for Azure and Azure OpenAI integrations.
- Strong input typing with Pydantic.
- Destructive or sensitive AI-agent actions are denied or require approval.
- AI analysis is not trusted until evaluation passes.
- Evidence packages include timestamped metadata and SHA-256 hashes.
- Missing model ownership is treated as governance risk.

## Compliance Frameworks

- ISO 27001
- NIST 800-53
- DORA
- CIS Controls
- SOC 2 placeholder controls
- AI governance / model risk controls

## AI Governance Model

The project treats AI governance as a first-class operating model:

- discover AI systems
- assign accountable owners
- score model risk
- require approval for production use
- verify logging and evaluation evidence
- enforce deterministic agent policies
- generate evidence for audits and governance reviews

## Evidence Generation

Generated artifacts:

- `reports/evidence_<finding_id>.json`
- `reports/evidence_<finding_id>.md`
- `reports/model_evidence_<model_id>.json`
- `reports/model_evidence_<model_id>.md`
- `reports/executive_summary.md`

## Local Demo Mode

Local demo mode is the default. It uses realistic sample data for findings, model deployments, ML models, and AI-agent traces. No Azure credentials are required.

## Future Azure Discovery Mode

`models_inventory/azure_discovery.py` now supports live Azure model discovery for:

- Azure OpenAI / Azure AI Services accounts and deployments
- Azure Machine Learning workspaces
- Azure Machine Learning online endpoints and deployments
- Azure Machine Learning registered models

Authentication supports multiple credential paths:

- service principal values in `.env`
- `az login` on the workstation
- managed identity when hosted on Azure

Use `AZURE_AUTH_MODE=auto` to let the app fall back from the service principal to Azure CLI.

Current live-mode scope:

- model inventory is live and replaceable from the dashboard or CLI
- model risk scoring is live because it runs on discovered Azure properties and tags
- security findings can be refreshed live from Azure Policy and Azure Activity Log
- native Prowler JSON/CSV outputs can be folded into the live finding registry
- GitHub SARIF/SBOM artifacts can be folded into the live finding registry when configured

## CISO Walkthrough

### ISO 27001 A.12.4 Logging

ControlLens AI directly operationalizes A.12.4 by:

- ingesting cloud findings for missing diagnostic logging such as `AZURE-003`
- flagging AI/LLM deployments with `logging_enabled=false`
- recording AI-agent decisions and risky action attempts
- generating evidence packages that include log-related control mappings and audit summaries
- surfacing logging posture in the dashboard and executive summary

In a demo, show `AZURE-003`, then show `MODEL-001`, then open the evidence report and explain that the platform captures the control failure, governance impact, and the audit artifact needed to prove remediation.

### ISO 27001 A.5.1 Policies For AI

ISO 27001 A.5.1 is about approved policy direction. In this platform, that becomes concrete AI governance rather than a policy PDF sitting on SharePoint. ControlLens AI implements that by:

- maintaining AI inventory and ownership
- requiring approval before production AI use
- mapping models to AI governance controls like `AI-APP-001`, `AI-OWN-001`, and `AI-AGENT-001`
- enforcing `governance/policy.yaml` for agent actions
- producing policy decision logs and model governance evidence

In a demo, show the denied `delete_resource` action, the `approve_model` decision requiring approval, and the model records with missing owners. That makes the policy real, testable, and auditable.

## How To Demo This To A CISO In 5 Minutes

1. Run `python cli.py demo`.
2. Open the Streamlit dashboard with `./start.sh`.
3. Start on Executive Overview and state the top-line risk posture.
4. Drill into `AZURE-003` to show logging gaps and ISO mappings.
5. Drill into `MODEL-001` to show missing owner, missing approval, and high model risk.
6. Show Governance Decisions and the denied `delete_resource` action.
7. Open Evidence Reports and show that every artifact is hash-backed and audit ready.

## Roadmap

- Real Azure Resource Graph and Azure ML discovery.
- Multi-tenant discovery across subscriptions and management groups.
- Stronger evidence lineage and immutable storage.
- Human workflow integration for approvals and exceptions.
- SIEM, ticketing, and CMDB integrations.
- More advanced evaluation frameworks and red-team datasets.

## Limitations

- The MVP uses JSON persistence instead of a production database.
- Azure discovery is abstracted, not tenant-live.
- Azure OpenAI analysis falls back to deterministic local generation unless credentials are supplied.
- Braintrust and LangChain OpenEvals are optional wrappers, not required runtime dependencies.

## Future Enterprise Deployment On Azure

- Run FastAPI in Azure Container Apps or AKS.
- Run Streamlit in Container Apps or App Service.
- Store evidence in Azure Blob Storage.
- Replace JSON state with Azure Database for PostgreSQL or Cosmos DB.
- Integrate discovery with Azure Resource Graph, Azure AI Foundry, Azure ML, Defender, and Log Analytics.
- Use Entra ID, Managed Identity, and Key Vault for authentication and secrets.

## LangChain Guidance

LangChain is not required for the current MVP. The project is stronger without it at this stage because:

- the workflow is deterministic and audit-oriented
- policy enforcement should stay explicit
- local demo startup stays faster and simpler

LangChain becomes useful later if you want:

- agent tool orchestration across many systems
- trace capture and observability
- retrieval pipelines for policy and evidence knowledge bases
- evaluation workflow reuse at larger scale

## CV Bullet

Built ControlLens AI, a Python-based AI Security & Compliance Control Tower that unifies cloud findings, AI/LLM inventory, model governance, policy enforcement, LLM evaluation, and audit evidence generation through FastAPI, Streamlit, and Docker.

## Interview Talking Points

- Why JSON persistence was acceptable for a fast enterprise prototype.
- How AI governance was made testable through policy checks and owner requirements.
- Why evidence generation is more valuable to executives than raw security alerts.
- How local deterministic fallbacks de-risk demos and early adoption.

## LinkedIn / GitHub Description

ControlLens AI is a local-first AI security and compliance platform that correlates cloud findings, AI model inventory, governance policy decisions, and audit evidence into one CISO-ready control tower.
