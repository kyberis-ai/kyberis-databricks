# Permissions

Least-privilege map of who needs what.

## Workspace roles

| Actor | Needs | Why |
|---|---|---|
| Workspace admin (one-time) | Create secret scope + ACLs; create the Databricks App and its secret resources | Setup only |
| Analyst using the app | **Can use** on the app | Opens the app; never sees credentials |
| Analyst running notebooks | **READ** on the `kyberis` secret scope; access to the Git folder; cluster attach | `dbutils.secrets.get` of the API key |
| Job service principal | **READ** on the `kyberis` secret scope; read on source table, write on output table | Scheduled enrichment runs |
| App service principal | **READ** on the `kyberis` secret scope (granted automatically via app secret resources) | Injecting env vars at app start |

## What the integration does NOT need

- No workspace admin rights at runtime.
- No Unity Catalog metastore privileges beyond the tables you point the
  notebooks at.
- No cluster-scoped init scripts, no cluster environment variables.
- No permissions in the Kyberis product beyond a standard customer API key
  with default read scopes; the integration performs read-only enrichment
  calls and never mutates Kyberis data.

## Sharing outputs

Enrichment output tables contain threat verdicts about your indicators —
treat them like any security telemetry: grant table access via Unity Catalog
to the security team's groups, and avoid granting broad workspace-wide
SELECT. Nothing in the output rows contains credentials (see
[privacy.md](privacy.md)).
