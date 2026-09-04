# Credential setup

Everything here follows one rule: **the Kyberis API key exists only in
Databricks secret storage.** It is never placed in notebooks, widgets, job
parameters, cluster environment variables, workspace files, or repo files —
all of those are readable by other users or end up in logs/exports.

## Get an API key

Create an API key in the Kyberis dashboard (Settings → API keys). You get a
`key id` and a `secret`. The integration needs the standard customer read
scopes (resolution, evidence, relationships, intel, assessments, batch);
the default key scopes cover this.

## Store it in a secret scope

```bash
databricks secrets create-scope kyberis
databricks secrets put-secret kyberis kyberis-api-key-id      # paste the key id
databricks secrets put-secret kyberis kyberis-api-key-secret  # paste the secret
```

Grant analysts/jobs that run the notebooks **READ** on the scope:

```bash
databricks secrets put-acl kyberis <user-or-group> READ
```

Notebooks read it with `dbutils.secrets.get`, which Databricks **redacts in
cell output** — the value cannot be casually printed. The helper package
immediately exchanges it for a short-lived bearer token (~30 min TTL), so
requests carry the long-lived secret only on the mint call
(`POST /v2/auth/token`), not on every enrichment call.

## Databricks App

The app never touches secret scopes directly. When creating/editing the app,
add two **Secret resources**:

| Resource key (used in `app.yaml` `valueFrom`) | Points at |
|---|---|
| `kyberis-api-key-id` | scope `kyberis`, key `kyberis-api-key-id` |
| `kyberis-api-key-secret` | scope `kyberis`, key `kyberis-api-key-secret` |

Databricks injects them as environment variables (`KYBERIS_API_KEY_ID`,
`KYBERIS_API_KEY_SECRET`) into the app process only, and grants the app's
service principal READ on the scope. The app renders neither value and its
`KyberisCredentials` type redacts the secret from `repr()`/exceptions.

## Rotation

1. Create a new API key in the Kyberis dashboard.
2. `databricks secrets put-secret` both keys with the new values.
3. Restart the app (Compute → Apps → Stop/Start) so it re-reads the env;
   notebooks/jobs pick the new values up on their next run.
4. Revoke the old key in Kyberis.

Note: revoking a Kyberis API key blocks *future* bearer-token mints; a token
minted just before revocation stays valid until it expires (≤30 minutes).

## Base URL

Optional `KYBERIS_API_BASE_URL` (env var, or leave the code default
`https://api.kyberis.ai`). Only https URLs should ever be used.
