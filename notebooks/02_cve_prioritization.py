# Databricks notebook source
# MAGIC %md
# MAGIC # Kyberis environment-driven prioritization
# MAGIC
# MAGIC Ask Kyberis what to investigate first for *your* environment, then
# MAGIC deep-dive the top-ranked CVE with a type-specific assessment.
# MAGIC
# MAGIC Prerequisites are the same as notebook 01 (secret scope + Git folder).

# COMMAND ----------

dbutils.widgets.text("secret_scope", "kyberis", "Secret scope")
dbutils.widgets.text("industry", "financial services", "Industry")
dbutils.widgets.text("products", "Cisco ASA, Palo Alto PAN-OS, Microsoft Exchange", "Products (comma-separated)")
dbutils.widgets.text("geography", "United States", "Geography")
dbutils.widgets.text("time_window_days", "30", "Time window (days)")

# COMMAND ----------

import json
import os
import sys

repo_root = os.path.dirname(os.getcwd())
for entry in (os.path.join(repo_root, "src"), os.path.join(repo_root, "vendor")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from kyberis_core import KyberisClient, KyberisClientConfig, tool_by_name
from kyberis_databricks import BearerTokenSession, build_agent_context, load_credentials_from_secrets, new_run_id
from kyberis_databricks.auth import base_url_from_env

client = KyberisClient(KyberisClientConfig(base_url=base_url_from_env()))
credentials = load_credentials_from_secrets(dbutils.secrets.get, dbutils.widgets.get("secret_scope"))
session = BearerTokenSession(client, credentials)
run_id = new_run_id("prio")

# COMMAND ----------

# Rank environment-relevant signals for immediate attention.
environment = {
    "industry": dbutils.widgets.get("industry"),
    "products": [product.strip() for product in dbutils.widgets.get("products").split(",") if product.strip()],
    "geography": dbutils.widgets.get("geography"),
}

response = client.call_tool(
    tool_by_name("prioritize"),
    {
        "agent_context": build_agent_context(
            "Rank threat signals for this environment for immediate attention",
            "Ranked signals with reasons",
            workflow_stage="assessment",
            run_id=run_id,
            step_id="prioritize",
        ),
        "environment": environment,
        "time_window_days": int(dbutils.widgets.get("time_window_days")),
        "max_items": 20,
    },
    auth_header=session.auth_header(),
)
assert response.status_code == 200, f"prioritize failed: HTTP {response.status_code}: {response.body}"

body = response.body if isinstance(response.body, dict) else {}
signals = body.get("items") or body.get("signals") or []
print(json.dumps(signals[:5], indent=2, default=str) if signals else "No signals returned.")

# COMMAND ----------

# Deep-dive the top-ranked CVE (if any) with a type-specific assessment.
top_cve = None
for signal in signals if isinstance(signals, list) else []:
    text = json.dumps(signal, default=str)
    if "CVE-" in text:
        resolution = signal.get("resolution") if isinstance(signal, dict) else None
        canonical = (resolution or {}).get("canonical_id") if isinstance(resolution, dict) else None
        top_cve = canonical or next(
            (token.strip('",') for token in text.split() if token.strip('",').startswith("CVE-")), None
        )
        break

if top_cve:
    assessment = client.call_tool(
        tool_by_name("cve_assessment"),
        {
            "agent_context": build_agent_context(
                "Assess the top-ranked CVE for this environment",
                "Urgency, score, actions, caveats",
                workflow_stage="assessment",
                run_id=run_id,
                step_id="cve-assess",
            ),
            "query": top_cve,
            "environment_context": environment,
        },
        auth_header=session.auth_header(),
    )
    print(f"cve_assessment({top_cve}) -> HTTP {assessment.status_code}")
    print(json.dumps(assessment.body, indent=2, default=str))
else:
    print("No CVE among the top signals — nothing to deep-dive.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Next steps
# MAGIC - Feed real asset/product inventory into `environment` from your
# MAGIC   lakehouse tables instead of widgets.
# MAGIC - Batch-assess a CVE shortlist with `assessments_batch`
# MAGIC   (`kyberis_databricks.enrich` shows the per-item handling pattern).
