"""Kyberis Threat Intelligence — Databricks App.

Streamlit app for interactive threat investigation against the Kyberis API:
single indicator/entity lookups, paste-a-list batch enrichment with CSV
export, and intel search.

Credentials arrive only as environment variables mapped from the app's
secret resources (see app.yaml); they are never rendered, logged, or written
to workspace files.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for entry in (REPO_ROOT / "src", REPO_ROOT / "vendor"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import pandas as pd
import streamlit as st
from kyberis_core import KyberisClient, KyberisClientConfig, KyberisClientError, tool_by_name
from kyberis_databricks import (
    BearerTokenSession,
    KyberisAuthError,
    KyberisPlanLimitError,
    assess_iocs,
    build_agent_context,
    load_credentials_from_env,
    new_run_id,
)
from kyberis_databricks.auth import base_url_from_env

st.set_page_config(page_title="Kyberis Threat Intelligence", page_icon="🛡️", layout="wide")

DEFAULT_OBJECTIVE = "Interactive threat investigation from the Kyberis Databricks app"

ENTITY_TYPES = ["ip", "domain", "url", "hash", "email", "cve", "actor", "malware", "campaign"]

ASSESSMENT_TOOL_BY_TYPE = {
    "ip": "ioc_assessment",
    "domain": "ioc_assessment",
    "url": "ioc_assessment",
    "hash": "ioc_assessment",
    "email": "ioc_assessment",
    "cve": "cve_assessment",
    "actor": "actor_assessment",
}


@st.cache_resource
def get_session() -> tuple[KyberisClient, BearerTokenSession, str]:
    base_url = base_url_from_env()
    client = KyberisClient(KyberisClientConfig(base_url=base_url))
    credentials = load_credentials_from_env()
    return client, BearerTokenSession(client, credentials), base_url


def call(tool_name: str, args: dict, *, stage: str, step_id: str):
    client, session, _ = get_session()
    args = {
        **args,
        "agent_context": build_agent_context(
            st.session_state.get("objective") or DEFAULT_OBJECTIVE,
            "Decision-ready threat context for an analyst",
            workflow_stage=stage,
            run_id=st.session_state["run_id"],
            step_id=step_id,
        ),
    }
    response = client.call_tool(tool_by_name(tool_name), args, auth_header=session.auth_header())
    if response.status_code in (401, 403):
        raise KyberisAuthError(f"The Kyberis API rejected the app credentials (HTTP {response.status_code}).")
    return response


def show_error(error: Exception) -> None:
    if isinstance(error, KyberisAuthError):
        st.error(
            f"**Credential problem.** {error}\n\n"
            "A workspace admin can fix the app's secret resources — see docs/credentials.md."
        )
    elif isinstance(error, KyberisPlanLimitError):
        st.warning(f"**Kyberis plan limit reached.** {error} Partial results are shown below.")
    elif isinstance(error, KyberisClientError):
        st.error(
            f"**Kyberis API unreachable.** {error}\n\n"
            "Check outbound HTTPS access to the Kyberis API from this workspace (docs/network.md)."
        )
    else:
        st.error(f"Unexpected error: {error}")


if "run_id" not in st.session_state:
    st.session_state["run_id"] = new_run_id("app")

st.title("🛡️ Kyberis Threat Intelligence")

try:
    _, _, active_base_url = get_session()
except KyberisAuthError as error:
    show_error(error)
    st.stop()

with st.sidebar:
    st.caption(f"API: `{active_base_url}`")
    st.caption(f"Session run id: `{st.session_state['run_id']}`")
    st.text_input(
        "Investigation objective",
        key="objective",
        placeholder=DEFAULT_OBJECTIVE,
        help="Sent as agent_context.objective with every API call (8-280 chars).",
    )
    st.markdown("---")
    st.markdown(
        "Docs: [install](https://github.com/kyberis-ai/kyberis-databricks/blob/main/docs/install.md) · "
        "[privacy](https://github.com/kyberis-ai/kyberis-databricks/blob/main/docs/privacy.md)"
    )

lookup_tab, batch_tab, intel_tab = st.tabs(["Indicator lookup", "Batch enrichment", "Intel search"])

with lookup_tab:
    with st.form("lookup"):
        column_query, column_types = st.columns([3, 2])
        query = column_query.text_input("Indicator, CVE, actor, malware, or campaign", placeholder="e.g. 185.220.101.4 or CVE-2024-3400 or APT29")
        expected_types = column_types.multiselect("Expected types (narrows resolution)", ENTITY_TYPES)
        submitted = st.form_submit_button("Investigate", type="primary")

    if submitted and query.strip():
        try:
            with st.spinner("Resolving entity…"):
                resolution_args: dict = {"query": query.strip()}
                if expected_types:
                    resolution_args["expected_types"] = expected_types
                response = call("entity_resolution", resolution_args, stage="resolve", step_id="lookup-resolve")

            body = response.body if isinstance(response.body, dict) else {}
            resolution = body.get("resolution") if isinstance(body.get("resolution"), dict) else {}
            resolution_status = str(resolution.get("status") or "unknown")
            entity_type = str(resolution.get("entity_type") or "")

            column_a, column_b, column_c, column_d = st.columns(4)
            column_a.metric("Resolution", resolution_status)
            column_b.metric("Entity type", entity_type or "—")
            column_c.metric("Canonical", str(resolution.get("canonical_name") or resolution.get("canonical_id") or "—"))
            confidence = resolution.get("confidence")
            column_d.metric("Confidence", f"{confidence:.2f}" if isinstance(confidence, (int, float)) else "—")

            if resolution_status == "ambiguous":
                st.info("Resolution is ambiguous — narrow the expected types and retry.")
            with st.expander("Resolution response"):
                st.json(body)

            assessment_tool = ASSESSMENT_TOOL_BY_TYPE.get(entity_type, "threat_assessment")
            with st.spinner(f"Running {assessment_tool}…"):
                canonical_id = str(resolution.get("canonical_id") or "")
                if resolution_status == "resolved" and canonical_id and entity_type:
                    assessment_args = {"subject": {"entity_type": entity_type, "canonical_id": canonical_id}}
                else:
                    assessment_args = {"query": query.strip()}
                assessment = call(assessment_tool, assessment_args, stage="assessment", step_id="lookup-assess")

            assessment_body = assessment.body if isinstance(assessment.body, dict) else {}
            priority = assessment_body.get("priority") if isinstance(assessment_body.get("priority"), dict) else {}
            signals = assessment_body.get("signals") if isinstance(assessment_body.get("signals"), dict) else {}
            column_a, column_b, column_c, column_d = st.columns(4)
            column_a.metric("Urgency", str(priority.get("decision_urgency") or "—"))
            score = priority.get("ranking_score", signals.get("ranking_score"))
            column_b.metric("Score", f"{score:.1f}" if isinstance(score, (int, float)) else "—")
            column_c.metric("Environment threat", str(signals.get("environment_threat") or "—"))
            column_d.metric("Action confidence", str(signals.get("action_confidence") or "—"))

            for label, key in (("Recommended actions", "recommended_actions"), ("Caveats", "caveats")):
                values = assessment_body.get(key)
                if isinstance(values, list) and values:
                    st.markdown(f"**{label}:**")
                    for value in values:
                        st.markdown(f"- {value}")
            with st.expander(f"{assessment_tool} response"):
                st.json(assessment_body)
        except Exception as error:  # surfaced to the analyst, never swallowed
            show_error(error)

with batch_tab:
    st.markdown(
        "Paste indicators (IPs, domains, URLs, hashes, emails) — one per line, "
        "up to a few hundred. They are deduplicated and enriched in batches of 50."
    )
    with st.form("batch"):
        raw = st.text_area("Indicators", height=180, placeholder="185.220.101.4\nbad-domain.example\n…")
        submitted = st.form_submit_button("Enrich", type="primary")

    if submitted:
        iocs = [line.strip() for line in raw.splitlines() if line.strip()]
        if not iocs:
            st.info("Nothing to enrich.")
        else:
            client, session, _ = get_session()
            rows: list[dict] = []
            try:
                with st.spinner(f"Enriching {len(iocs)} indicators…"):
                    rows = assess_iocs(
                        client,
                        session.auth_header,
                        iocs,
                        objective=st.session_state.get("objective") or DEFAULT_OBJECTIVE,
                        run_id=st.session_state["run_id"],
                    )
            except KyberisPlanLimitError as error:
                show_error(error)
                rows = error.rows
            except Exception as error:
                show_error(error)

            if rows:
                frame = pd.DataFrame(rows).drop(columns=["raw"])
                ok_count = int((frame["status"] == "ok").sum())
                st.caption(f"{ok_count}/{len(frame)} enriched (status != ok rows explain themselves).")
                st.dataframe(frame, width="stretch", hide_index=True)
                st.download_button(
                    "Download CSV",
                    frame.to_csv(index=False).encode("utf-8"),
                    file_name="kyberis_enrichment.csv",
                    mime="text/csv",
                )

with intel_tab:
    with st.form("intel"):
        column_query, column_window = st.columns([4, 1])
        intel_query = column_query.text_input("Topic, campaign, or question", placeholder="e.g. ransomware targeting healthcare")
        window_days = column_window.number_input("Window (days)", min_value=1, max_value=365, value=30)
        submitted = st.form_submit_button("Search", type="primary")

    if submitted and intel_query.strip():
        try:
            with st.spinner("Searching intel…"):
                response = call(
                    "intel_search",
                    {"query": intel_query.strip(), "time_window_days": int(window_days), "max_results": 20},
                    stage="other",
                    step_id="intel-search",
                )
            body = response.body if isinstance(response.body, dict) else {}
            results = body.get("results")
            if not isinstance(results, list) or not results:
                st.info("No intel capsules matched.")
            for result in results if isinstance(results, list) else []:
                if not isinstance(result, dict):
                    continue
                title = str(result.get("title") or result.get("summary") or "Intel capsule")
                with st.expander(title):
                    st.json(result)
        except Exception as error:
            show_error(error)
