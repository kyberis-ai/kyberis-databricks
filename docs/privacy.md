# Data handling and privacy

## What leaves Databricks

Requests to the Kyberis API contain exactly:

- **The indicators/queries you enrich** — IOC values (IPs, domains, URLs,
  hashes, emails), CVE ids, actor/malware/campaign names, or intel search
  text you type or select.
- **Environment context you explicitly provide** — e.g. the
  industry/products/geography widgets in notebook 02.
- **`agent_context` metadata** — objective and requested-outcome strings
  (static defaults unless you override them), a workflow stage, and random
  run/step ids. Nothing here is derived from your table contents.
- **Credentials** — the API key on the token-mint call only; short-lived
  bearer tokens on enrichment calls.

Not sent, by design: table names, schemas, row contents beyond the selected
indicator column, cluster/workspace identifiers, user identities, or
notebook code.

## What is stored where

| Data | Location | Notes |
|---|---|---|
| API key | Databricks secret scope / app secret resources only | Never in code, widgets, job params, or files ([credentials.md](credentials.md)) |
| Bearer tokens | App/notebook process memory | ≤30 min TTL, never persisted |
| Enrichment results | Wherever you write them (display only by default; Delta table if you set `output_table`) | Treat as security telemetry ([permissions.md](permissions.md)) |
| Kyberis-side processing | Kyberis platform | Governed by your Kyberis subscription terms; queries are processed to serve the response and product telemetry per contract |

## Logging and audit

- **Databricks side**: secret reads via `dbutils.secrets.get` are redacted
  in notebook output; secret-scope access and app lifecycle events appear in
  Databricks audit logs (`secrets` and `apps` event categories), so key
  access is attributable per user/principal.
- **Kyberis side**: every API call is logged against the API key's
  principal with the `agent_context` run/step ids. Use a distinct API key
  per workspace (or per team) so Kyberis-side usage and audit trails
  attribute cleanly, and pass a meaningful `run_id` (the helpers generate
  one per job run) to correlate a Databricks job run with Kyberis-side logs.
- **Error paths**: exception messages produced by this integration never
  include credential material; the `KyberisCredentials` type redacts the
  secret from `repr()`.

## Controls and opt-outs

- Enrich only columns you choose; the helpers never scan tables themselves.
- Set `objective` widgets/inputs to neutral text if your change-management
  requires it — they are free-text and default to static strings.
- To keep results out of persistent storage, leave `output_table` empty
  (display-only) and export nothing.
