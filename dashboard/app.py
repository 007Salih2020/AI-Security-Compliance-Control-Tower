from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Dict, List

import pandas as pd
import streamlit as st

from ai.executive_summary import build_demo_summary
from app.database import get_db
from app.models import ModelInventoryRecord, NormalizedFinding
from app.services import ensure_demo_state, refresh_live_azure_models, refresh_live_security_findings, run_demo


def main() -> None:
    st.set_page_config(page_title="ControlLens AI", page_icon="🛡️", layout="wide")
    _inject_styles()

    db = get_db()
    if not db.get_findings() or not db.get_reports():
        with st.spinner("Preparing demo data and reports..."):
            run_demo()
    else:
        ensure_demo_state()

    summary = build_demo_summary()
    findings = db.get_findings()
    models = db.get_models()
    reports = db.get_reports()
    decisions = db.get_governance_decisions()

    st.title("ControlLens AI")
    st.caption("AI Security & Compliance Control Tower")

    with st.sidebar:
        st.subheader("Control Tower")
        page = st.radio(
            "Select View",
            [
                "Executive Overview",
                "Security Findings",
                "Compliance Coverage",
                "AI / LLM Inventory",
                "Model Risk Registry",
                "Governance Decisions",
                "Evidence Reports",
            ],
        )
        if st.button("Rebuild Demo Evidence", use_container_width=True):
            with st.spinner("Rebuilding demo flow..."):
                run_demo()
            st.rerun()
        if st.button("Refresh Live Azure Inventory", use_container_width=True):
            with st.spinner("Pulling live Azure AI/ML inventory..."):
                try:
                    refresh_live_azure_models(generate_evidence=True)
                except Exception as exc:
                    st.error(
                        "Live Azure discovery failed. Verify AZURE_SUBSCRIPTION_ID and either the service principal "
                        "environment variables or az login, then try again.\n\n"
                        f"Error: {exc}"
                    )
                else:
                    st.success("Live Azure model inventory refreshed.")
                    st.rerun()
        if st.button("Refresh Live Security Findings", use_container_width=True):
            with st.spinner("Pulling live Azure and DevSecOps security findings..."):
                try:
                    sync_summary = refresh_live_security_findings(generate_evidence=True)
                except Exception as exc:
                    st.error(
                        "Live security sync failed. Verify Azure permissions and any optional Prowler or GitHub "
                        f"artifact configuration, then try again.\n\nError: {exc}"
                    )
                else:
                    if sync_summary.warnings:
                        st.warning("\n".join(sync_summary.warnings[:5]))
                    st.success(
                        f"Live security sync completed. Findings ingested: {sync_summary.findings_ingested}. "
                        f"Mode: {sync_summary.mode}."
                    )
                    st.rerun()
        st.caption(
            "Live refresh supports Azure Policy, Azure Activity Log, optional native Prowler outputs, and optional "
            "GitHub SARIF/SBOM artifacts when configured."
        )

    if page == "Executive Overview":
        render_executive_overview(summary, findings, models)
    elif page == "Security Findings":
        render_security_findings(findings)
    elif page == "Compliance Coverage":
        render_compliance_coverage(findings, models)
    elif page == "AI / LLM Inventory":
        render_inventory(summary, models)
    elif page == "Model Risk Registry":
        render_model_registry(models)
    elif page == "Governance Decisions":
        render_governance(decisions)
    else:
        render_reports(reports)


def _inject_styles() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background:
                radial-gradient(circle at top left, rgba(16,185,129,0.18), transparent 26%),
                radial-gradient(circle at top right, rgba(245,158,11,0.18), transparent 22%),
                linear-gradient(180deg, #071118 0%, #0f1722 100%);
            color: #f4f7fb;
        }
        .metric-card {
            padding: 1rem;
            border-radius: 16px;
            background: rgba(15, 23, 34, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.08);
        }
        .summary-banner {
            padding: 1.2rem;
            border-radius: 18px;
            background: linear-gradient(135deg, rgba(16,185,129,0.22), rgba(245,158,11,0.16));
            border: 1px solid rgba(255,255,255,0.08);
            margin-bottom: 1rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_executive_overview(summary, findings: List[NormalizedFinding], models: List[ModelInventoryRecord]) -> None:
    st.markdown(
        f"""
        <div class="summary-banner">
            <h3 style="margin:0 0 0.5rem 0;">CISO Summary</h3>
            <p style="margin:0;">
                ControlLens AI discovered {summary.models_discovered} AI/LLM deployments,
                {summary.models_missing_owners} have missing owners, {summary.high_risk_models} are high-risk,
                and {summary.governance_denials} governance denials were recorded.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Findings", summary.findings_ingested)
    col2.metric("Critical/High Findings", len([f for f in findings if f.risk_rating in {"Critical", "High"}]))
    col3.metric("Discovered Models", summary.models_discovered)
    col4.metric("Evidence Reports", summary.evidence_reports_generated)

    col5, col6, col7, col8 = st.columns(4)
    col5.metric("High-Risk Models", summary.high_risk_models)
    col6.metric("Missing Owners", summary.models_missing_owners)
    col7.metric("Compliance Mappings", summary.controls_mapped)
    col8.metric("AI Eval Pass Rate", summary.evaluations_passed)

    st.subheader("Top Risks")
    top_findings = pd.DataFrame(
        [
            {
                "Finding ID": finding.finding_id,
                "Title": finding.title,
                "Risk Rating": finding.risk_rating,
                "Score": finding.risk_score,
                "Resource": finding.resource_name,
            }
            for finding in sorted(findings, key=lambda item: item.risk_score, reverse=True)[:5]
        ]
    )
    top_models = pd.DataFrame(
        [
            {
                "Model ID": model.model_inventory_id,
                "Model": model.model_name,
                "Owner": model.owner,
                "Risk Tier": model.risk_tier,
                "Score": model.risk_score,
            }
            for model in sorted(models, key=lambda item: item.risk_score, reverse=True)[:5]
        ]
    )
    left, right = st.columns(2)
    left.dataframe(top_findings, use_container_width=True, hide_index=True)
    right.dataframe(top_models, use_container_width=True, hide_index=True)


def render_security_findings(findings: List[NormalizedFinding]) -> None:
    st.subheader("Security Findings")
    findings_df = pd.DataFrame([finding.model_dump(mode="json") for finding in findings])
    if findings_df.empty:
        st.info("No findings available.")
        return

    c1, c2 = st.columns(2)
    c1.bar_chart(findings_df["severity"].value_counts())
    c2.bar_chart(findings_df["source_tool"].value_counts())

    top_assets = findings_df.groupby("resource_name")["risk_score"].max().sort_values(ascending=False)
    st.bar_chart(top_assets.head(10))

    display_columns = ["finding_id", "title", "severity", "risk_rating", "risk_score", "resource_name", "source_tool"]
    st.dataframe(findings_df[display_columns], use_container_width=True, hide_index=True)


def render_compliance_coverage(findings: List[NormalizedFinding], models: List[ModelInventoryRecord]) -> None:
    st.subheader("Compliance Coverage")
    controls = []
    for finding in findings:
        controls.extend(control.model_dump(mode="json") for control in finding.mapped_controls)
    for model in models:
        controls.extend(control.model_dump(mode="json") for control in model.compliance_mappings)

    controls_df = pd.DataFrame(controls)
    if controls_df.empty:
        st.info("No control mappings available.")
        return

    framework_counts = controls_df["framework"].value_counts()
    st.bar_chart(framework_counts)
    st.dataframe(
        controls_df[["framework", "control_id", "control_name", "risk_domain"]].drop_duplicates(),
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("### ISO 27001 Focus")
    iso_df = controls_df[controls_df["framework"] == "ISO 27001"]
    st.dataframe(iso_df[["control_id", "control_name", "risk_domain"]].drop_duplicates(), use_container_width=True, hide_index=True)


def render_inventory(summary, models: List[ModelInventoryRecord]) -> None:
    st.subheader("AI / LLM Inventory")
    models_df = pd.DataFrame([model.model_dump(mode="json") for model in models])
    if models_df.empty:
        st.info("No models available.")
        return

    st.markdown(
        f"""
        <div class="summary-banner">
            <p style="margin:0;">
                ControlLens AI discovered {summary.models_discovered} AI/LLM deployments,
                {summary.models_missing_owners} have missing owners, {summary.high_risk_models} are high-risk,
                and {len(models_df[models_df['governance_review_required']])} require governance review.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Platforms", models_df["platform"].nunique())
    c2.metric("Production Models", len(models_df[models_df["environment"] == "production"]))
    c3.metric("Internet Accessible", int(models_df["internet_accessible"].sum()))
    c4.metric("Used by Agents", int(models_df["used_by_agent"].sum()))

    left, right = st.columns(2)
    left.bar_chart(models_df["platform"].value_counts())
    right.bar_chart(models_df["risk_tier"].value_counts())

    st.dataframe(
        models_df[
            [
                "model_inventory_id",
                "model_name",
                "platform",
                "owner",
                "application_name",
                "risk_tier",
                "risk_score",
                "approval_status",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )


def render_model_registry(models: List[ModelInventoryRecord]) -> None:
    st.subheader("Model Risk Registry")
    models_df = pd.DataFrame([model.model_dump(mode="json") for model in models])
    if models_df.empty:
        st.info("No model registry entries available.")
        return

    top_high_risk = models_df.sort_values("risk_score", ascending=False).head(5)
    st.dataframe(
        top_high_risk[
            [
                "model_inventory_id",
                "model_name",
                "owner",
                "risk_tier",
                "risk_score",
                "missing_fields",
                "recommended_actions",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

    missing_owner_df = models_df[models_df["owner"].str.lower() == "unknown"]
    missing_eval_df = models_df[models_df["evaluation_available"] == False]
    c1, c2 = st.columns(2)
    c1.dataframe(missing_owner_df[["model_inventory_id", "model_name", "application_name"]], use_container_width=True, hide_index=True)
    c2.dataframe(missing_eval_df[["model_inventory_id", "model_name", "application_name"]], use_container_width=True, hide_index=True)


def render_governance(decisions) -> None:
    st.subheader("Governance Decisions")
    decisions_df = pd.DataFrame([decision.model_dump(mode="json") for decision in decisions])
    if decisions_df.empty:
        st.info("No governance decisions available.")
        return

    counts = decisions_df["decision"].value_counts()
    st.bar_chart(counts)
    risky_attempts = decisions_df[decisions_df["action"].isin(["delete_resource", "disable_logging", "approve_model"])]
    st.dataframe(risky_attempts[["action", "decision", "matched_rule", "reason", "timestamp"]], use_container_width=True, hide_index=True)


def render_reports(reports) -> None:
    st.subheader("Evidence Reports")
    for report in reports:
        with st.expander(f"{report.target_type}: {report.target_id}"):
            st.write(f"Evidence ID: {report.evidence_id}")
            st.write(f"Summary: {report.summary}")
            st.write(f"SHA256: {report.sha256}")
            if report.markdown_path and Path(report.markdown_path).exists():
                path = Path(report.markdown_path)
                content = path.read_text(encoding="utf-8")
                st.download_button(
                    label=f"Download {path.name}",
                    data=content,
                    file_name=path.name,
                    mime="text/markdown",
                    key=f"md-{report.evidence_id}",
                )
                st.code(content[:2000])
            if report.json_path and Path(report.json_path).exists():
                path = Path(report.json_path)
                content = path.read_text(encoding="utf-8")
                st.download_button(
                    label=f"Download {path.name}",
                    data=content,
                    file_name=path.name,
                    mime="application/json",
                    key=f"json-{report.evidence_id}",
                )


if __name__ == "__main__":
    main()
