# Databricks notebook source
# MAGIC %md
# MAGIC # Kyberis IOC batch enrichment
# MAGIC
# MAGIC Enrich a table (or demo list) of IOCs — IPs, domains, URLs, hashes,
# MAGIC emails — with Kyberis threat verdicts, and write the results to a
# MAGIC Delta table you can join back onto detections.
# MAGIC
# MAGIC **Before running** (see `docs/credentials.md`):
# MAGIC 1. Create a secret scope (default name `kyberis`) with keys
# MAGIC    `kyberis-api-key-id` and `kyberis-api-key-secret`.
# MAGIC 2. Run this notebook from the repo's Git folder so `src/` and
# MAGIC    `vendor/` import directly. (Alternative: `%pip install` the wheel
# MAGIC    from `make wheel` and skip the `sys.path` cell.)
# MAGIC
# MAGIC The API key secret never appears in this notebook's output: it is read
# MAGIC via `dbutils.secrets` (redacted in cell output) and exchanged for a
# MAGIC short-lived bearer token.

# COMMAND ----------

dbutils.widgets.text("secret_scope", "kyberis", "Secret scope")
dbutils.widgets.text("source_table", "", "Source table (empty = demo IOCs)")
dbutils.widgets.text("ioc_column", "ioc", "IOC column in source table")
dbutils.widgets.text("output_table", "", "Output Delta table (empty = display only)")
dbutils.widgets.text("objective", "Enrich detection IOCs with Kyberis threat verdicts", "Objective")

# COMMAND ----------

import os
import sys

# Import the helper package and vendored client from this Git folder.
repo_root = os.path.dirname(os.getcwd())
for entry in (os.path.join(repo_root, "src"), os.path.join(repo_root, "vendor")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from kyberis_core import KyberisClient, KyberisClientConfig
from kyberis_databricks import (
    BearerTokenSession,
    KyberisPlanLimitError,
    assess_iocs,
    load_credentials_from_secrets,
    new_run_id,
)
from kyberis_databricks.auth import base_url_from_env

# COMMAND ----------

client = KyberisClient(KyberisClientConfig(base_url=base_url_from_env()))
credentials = load_credentials_from_secrets(
    dbutils.secrets.get, dbutils.widgets.get("secret_scope")
)
session = BearerTokenSession(client, credentials)

# COMMAND ----------

source_table = dbutils.widgets.get("source_table").strip()
if source_table:
    ioc_column = dbutils.widgets.get("ioc_column").strip()
    iocs = [
        row[0]
        for row in spark.table(source_table).select(ioc_column).distinct().collect()
        if row[0]
    ]
else:
    # Demo indicators (documentation/test values, not live threats).
    iocs = ["198.51.100.23", "203.0.113.77", "test-malicious.example"]

print(f"{len(iocs)} distinct IOCs to enrich")

# COMMAND ----------

# Enriches in batches of up to 50. Every input yields exactly one row whose
# `status` column says what happened (ok / error / transport_error /
# plan_limit) — a partially failed run still returns usable rows.
run_id = new_run_id("job")
try:
    rows = assess_iocs(
        client,
        session.auth_header,
        iocs,
        objective=dbutils.widgets.get("objective"),
        run_id=run_id,
    )
except KyberisPlanLimitError as error:
    print(f"Plan limit reached — keeping {len(error.rows)} partial rows: {error}")
    rows = error.rows

print(f"{sum(1 for row in rows if row['status'] == 'ok')}/{len(rows)} enriched (run_id={run_id})")

# COMMAND ----------

from pyspark.sql import types as T

schema = T.StructType(
    [
        T.StructField("ioc", T.StringType()),
        T.StructField("status", T.StringType()),
        T.StructField("message", T.StringType()),
        T.StructField("urgency", T.StringType()),
        T.StructField("score", T.DoubleType()),
        T.StructField("threat", T.StringType()),
        T.StructField("action_confidence", T.StringType()),
        T.StructField("confidence", T.DoubleType()),
        T.StructField("resolution_status", T.StringType()),
        T.StructField("entity", T.StringType()),
        T.StructField("entity_type", T.StringType()),
        T.StructField("attributions", T.ArrayType(T.StringType())),
        T.StructField("mitre_techniques", T.ArrayType(T.StringType())),
        T.StructField("target_industries", T.ArrayType(T.StringType())),
        T.StructField("ioc_state", T.StringType()),
        T.StructField("recommended_actions", T.ArrayType(T.StringType())),
        T.StructField("caveats", T.ArrayType(T.StringType())),
        T.StructField("evidence_refs", T.ArrayType(T.StringType())),
        T.StructField("degraded", T.BooleanType()),
        T.StructField("degraded_reasons", T.ArrayType(T.StringType())),
        T.StructField("raw", T.StringType()),
    ]
)

enriched = spark.createDataFrame(rows, schema=schema)
display(enriched.drop("raw"))

# COMMAND ----------

output_table = dbutils.widgets.get("output_table").strip()
if output_table:
    enriched.write.mode("overwrite").saveAsTable(output_table)
    print(f"Wrote {enriched.count()} rows to {output_table}")
else:
    print("No output_table set — results displayed only.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Next steps
# MAGIC - Join `output_table` back onto your detections on the `ioc` column.
# MAGIC - Filter `urgency IN ('act_now', 'urgent')` for triage queues.
# MAGIC - Schedule this notebook as a job; pass `source_table`/`output_table`
# MAGIC   as job parameters. Rows with `status != 'ok'` explain themselves —
# MAGIC   retry `transport_error` rows, review `plan_limit` with your admin.
