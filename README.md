# Kyberis Threat Intelligence for Databricks

Bring Kyberis threat intelligence enrichment and investigation into
Databricks, where data and security teams already analyze operational and
detection data: batch-enrich IOC tables from notebooks and jobs, and
investigate indicators interactively in a Databricks App — all against the
Kyberis Threat Investigator API (`/v2`).

Requires a Kyberis subscription and API key ([kyberis.ai](https://kyberis.ai)).

## What you get

- **`kyberis_databricks` helper package** — credential loading from
  Databricks secret scopes or app environment variables, short-lived bearer
  token handling, and batched enrichment helpers
  (`assess_iocs`, `resolve_entities`) that return DataFrame-ready rows with a
  fixed schema. Pure standard library.
- **Databricks App** ([app/app.py](app/app.py)) — a Streamlit workspace app
  for interactive IOC/entity investigation: single lookups, paste-a-list
  batch enrichment with CSV export, and intel search.
- **Example notebooks** ([notebooks/](notebooks/)) — IOC batch enrichment
  into a Delta table, and environment-driven CVE prioritization.
- **Vendored API client** ([vendor/kyberis_core/](vendor/README.md)) — the
  shared Kyberis API client, dependency-free by design so vendoring is safe.

## Quickstart

### Notebooks / jobs (Git folder)

1. Add this repo as a Databricks Git folder (Repos).
2. Create a secret scope holding your API key
   (see [docs/credentials.md](docs/credentials.md)):

   ```bash
   databricks secrets create-scope kyberis
   databricks secrets put-secret kyberis kyberis-api-key-id
   databricks secrets put-secret kyberis kyberis-api-key-secret
   ```

3. Open [notebooks/01_ioc_batch_enrichment.py](notebooks/01_ioc_batch_enrichment.py)
   and run it. The notebooks import `src/` and `vendor/` from the Git folder
   directly — no wheel install needed. For non-Git-folder jobs, build a wheel
   with `make wheel` and `%pip install` it; the wheel ships both
   `kyberis_databricks` and `kyberis_core`.

### Databricks App

```bash
databricks apps create kyberis-threat-intelligence
databricks sync . /Workspace/Users/<you>/kyberis-databricks
databricks apps deploy kyberis-threat-intelligence \
  --source-code-path /Workspace/Users/<you>/kyberis-databricks
```

The app reads its API key from two app secret resources mapped to
`KYBERIS_API_KEY_ID` / `KYBERIS_API_KEY_SECRET` in [app.yaml](app.yaml) —
full steps in [docs/install.md](docs/install.md).

## Documentation

- [Installation](docs/install.md) — app deploy, Git folders, jobs,
  compatibility
- [Credential setup](docs/credentials.md) — secret scopes, app secret
  resources, rotation
- [Permissions](docs/permissions.md) — who needs what, app service principal,
  least privilege
- [Network requirements](docs/network.md) — egress to `api.kyberis.ai`,
  serverless/classic compute notes
- [Data handling and privacy](docs/privacy.md) — what leaves Databricks,
  what is stored where, audit logging

## Layout

```
app.yaml                 Databricks App entry point (repo root = app source root)
requirements.txt         App dependencies installed at deploy time
app/app.py               Streamlit investigation app
src/kyberis_databricks/  Helper package: auth, agent_context, batch enrichment
vendor/kyberis_core/     Vendored Kyberis API client (do not edit; see vendor/README.md)
notebooks/               Example notebooks (Databricks source format)
docs/                    User and admin documentation
tests/                   Hermetic pytest suite (no network, no Databricks runtime)
```

## Development

```bash
make test    # run the pytest suite (uv)
make wheel   # build dist/kyberis_databricks-<ver>.whl (includes kyberis_core)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and guidelines, and
[vendor/README.md](vendor/README.md) for how the vendored client is updated.

## Support and security

- Questions and bugs: [open an issue](https://github.com/kyberis-ai/kyberis-databricks/issues)
  or email support@kyberis.ai
- Security reports: see [SECURITY.md](SECURITY.md) — please do not file
  public issues for vulnerabilities

## License

[Apache 2.0](LICENSE). Use of the Kyberis API is governed by your Kyberis
subscription terms.
