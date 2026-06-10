from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ai.executive_summary import build_demo_summary, save_executive_summary
from app.config import get_settings
from app.services import (
    analyze_finding,
    discover_and_register_models,
    evaluate_finding,
    generate_finding_evidence,
    generate_model_evidence,
    get_high_risk_models,
    get_unknown_owner_models,
    ingest_demo,
    ingest_findings,
    list_findings,
    list_models,
    policy_check,
    refresh_live_security_findings,
    reset_state,
    rescore_registered_models,
    run_demo,
    update_model_owner,
)
from models_inventory.azure_discovery import AzureDiscoveryError
from models_inventory.registry import export_models
from scanners.azure_security_sync import AzureSecuritySyncError

app = typer.Typer(help="ControlLens AI command-line interface.")
models_app = typer.Typer(help="AI/LLM model inventory commands.")
model_owner_app = typer.Typer(help="Ownership enrichment commands.")
app.add_typer(models_app, name="models")
app.add_typer(model_owner_app, name="model-owner")
console = Console()


@app.command()
def demo() -> None:
    summary = run_demo()
    _print_demo_summary(summary)


@app.command("init-demo")
def init_demo() -> None:
    reset_state(clear_reports=True)
    ingest_demo()
    discover_and_register_models(source="local")
    console.print("[green]Demo state initialized with findings and models.[/green]")


@app.command()
def ingest(file: str = typer.Option(..., "--file", help="Path to a supported sample file.")) -> None:
    findings = ingest_findings(file)
    console.print(f"[green]Ingested {len(findings)} findings from {file}.[/green]")


@app.command()
def analyze(finding_id: str = typer.Option(..., "--finding-id")) -> None:
    finding = analyze_finding(finding_id)
    console.print(f"[green]Generated analysis for {finding.finding_id}.[/green]")
    console.print(finding.ai_analysis.executive_summary if finding.ai_analysis else "No analysis generated.")


@app.command()
def evaluate(finding_id: str = typer.Option(..., "--finding-id")) -> None:
    finding = evaluate_finding(finding_id)
    passed = sum(1 for result in finding.evaluations if result.pass_fail)
    console.print(f"[green]Evaluated {finding.finding_id}. Passed metrics: {passed}/{len(finding.evaluations)}[/green]")


@app.command()
def evidence(finding_id: str = typer.Option(..., "--finding-id")) -> None:
    metadata = generate_finding_evidence(finding_id)
    console.print(f"[green]Evidence created for {finding_id}: {metadata.markdown_path}[/green]")


@app.command("discover-models")
def discover_models(source: str = typer.Option("local", "--source")) -> None:
    try:
        models = discover_and_register_models(source=source)
    except AzureDiscoveryError as exc:
        console.print(f"[red]Azure discovery failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Discovered and registered {len(models)} models using source={source}.[/green]")


@app.command("sync-security")
def sync_security(
    lookback_hours: int = typer.Option(get_settings().azure_activity_log_lookback_hours, "--lookback-hours"),
    include_policy_states: bool = typer.Option(True, "--include-policy-states/--no-include-policy-states"),
    include_activity_log: bool = typer.Option(True, "--include-activity-log/--no-include-activity-log"),
    include_prowler: bool = typer.Option(True, "--include-prowler/--no-include-prowler"),
    include_github_artifacts: bool = typer.Option(True, "--include-github-artifacts/--no-include-github-artifacts"),
    replace_existing: bool = typer.Option(True, "--replace-existing/--merge"),
    generate_evidence: bool = typer.Option(True, "--generate-evidence/--no-generate-evidence"),
    evidence_limit: int = typer.Option(25, "--evidence-limit"),
) -> None:
    try:
        summary = refresh_live_security_findings(
            lookback_hours=lookback_hours,
            include_policy_states=include_policy_states,
            include_activity_log=include_activity_log,
            include_prowler=include_prowler,
            include_github_artifacts=include_github_artifacts,
            replace_existing=replace_existing,
            generate_evidence=generate_evidence,
            evidence_limit=evidence_limit,
        )
    except AzureSecuritySyncError as exc:
        console.print(f"[red]Azure security sync failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(
        f"[green]Live security sync completed.[/green] Findings ingested: {summary.findings_ingested} | "
        f"Mode: {summary.mode}"
    )
    if summary.source_counts:
        for source_name, count in summary.source_counts.items():
            console.print(f"- {source_name}: {count}")
    if summary.warnings:
        console.print("[yellow]Warnings:[/yellow]")
        for warning in summary.warnings:
            console.print(f"- {warning}")


@models_app.command("list")
def models_list() -> None:
    models = list_models()
    table = Table(title="Model Inventory")
    table.add_column("Model ID")
    table.add_column("Name")
    table.add_column("Owner")
    table.add_column("Env")
    table.add_column("Risk")
    for model in models:
        table.add_row(
            model.model_inventory_id,
            model.model_name,
            model.owner,
            model.environment,
            f"{model.risk_tier} ({model.risk_score})",
        )
    console.print(table)


@models_app.command("risk")
def models_risk() -> None:
    models = rescore_registered_models()
    console.print(f"[green]Rescored {len(models)} models.[/green]")
    for model in models:
        console.print(f"- {model.model_inventory_id}: {model.risk_tier} ({model.risk_score})")


@models_app.command("evidence")
def models_evidence(model_id: str = typer.Option(..., "--model-id")) -> None:
    metadata = generate_model_evidence(model_id)
    console.print(f"[green]Model evidence created for {model_id}: {metadata.markdown_path}[/green]")


@models_app.command("export")
def models_export(format: str = typer.Option("json", "--format")) -> None:
    console.print(export_models(format))


@model_owner_app.command("set")
def model_owner_set(
    model_id: str = typer.Option(..., "--model-id"),
    owner: str = typer.Option(..., "--owner"),
    business_unit: str = typer.Option(..., "--business-unit"),
    use_case: str = typer.Option(..., "--use-case"),
) -> None:
    model = update_model_owner(model_id, owner, business_unit, use_case)
    console.print(
        f"[green]Updated owner for {model.model_inventory_id}: {model.owner} / {model.business_unit} / {model.use_case}[/green]"
    )


@app.command("policy-check")
def policy_check_command(action: str = typer.Option(..., "--action")) -> None:
    decision = policy_check(action=action)
    console.print(f"[green]{decision.action} => {decision.decision} ({decision.reason})[/green]")


@app.command("executive-summary")
def executive_summary() -> None:
    path = save_executive_summary()
    summary = build_demo_summary()
    console.print(f"[green]Executive summary generated at {path}.[/green]")
    console.print(summary.ciso_message)


@app.command("run-api")
def run_api(
    host: str = typer.Option("0.0.0.0", "--host"),
    port: int = typer.Option(get_settings().default_api_port, "--port"),
) -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            host,
            "--port",
            str(port),
            "--reload",
        ],
        check=True,
    )


@app.command("dashboard")
def dashboard(
    port: int = typer.Option(get_settings().default_ui_port, "--port"),
) -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            "ui.py",
            "--server.port",
            str(port),
            "--server.address",
            "0.0.0.0",
        ],
        check=True,
    )


def _print_demo_summary(summary) -> None:
    console.print("[bold cyan]ControlLens AI Demo Complete[/bold cyan]\n")
    console.print(f"Security findings ingested: {summary.findings_ingested}")
    console.print(f"AI/LLM models discovered: {summary.models_discovered}")
    console.print(f"Models missing owners: {summary.models_missing_owners}")
    console.print(f"High-risk AI models: {summary.high_risk_models}")
    console.print(f"Critical security findings: {summary.critical_findings}")
    console.print(f"Controls mapped: {summary.controls_mapped}")
    console.print(f"AI analyses generated: {summary.analyses_generated}")
    console.print(f"Model risk assessments generated: {summary.model_risk_assessments_generated}")
    console.print(f"AI evaluations passed: {summary.evaluations_passed}")
    console.print(f"Governance denials: {summary.governance_denials}")
    console.print(f"Evidence reports generated: {summary.evidence_reports_generated}\n")
    console.print('[bold]CISO Message:[/bold]')
    console.print(f'“{summary.ciso_message}”')


if __name__ == "__main__":
    app()
