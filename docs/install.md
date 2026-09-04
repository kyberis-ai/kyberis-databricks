# Installation

Three ways to use Kyberis in Databricks, from lightest to most integrated.
All of them need a Kyberis API key ([credentials.md](credentials.md)) and
outbound HTTPS to the Kyberis API ([network.md](network.md)).

## Compatibility

| Component | Requirement |
|---|---|
| Notebooks / jobs | Databricks Runtime 13.3 LTS+ (Python 3.10+). No cluster libraries required — the client is vendored and stdlib-only. |
| Databricks App | Databricks Apps enabled in the workspace (Python 3.11 runtime). Only external dependency: `streamlit` (installed from `requirements.txt` at deploy). |
| Unity Catalog | Optional. Example notebooks write plain Delta tables; UC and hive_metastore both work. |
| Serverless compute | Supported if serverless egress allows `api.kyberis.ai` ([network.md](network.md)). |

## 1. Git folder + notebooks (recommended start)

1. In your workspace: **Workspace → Create → Git folder**, URL
   `https://github.com/kyberis-ai/kyberis-databricks.git`.
2. Set up credentials per [credentials.md](credentials.md).
3. Open `notebooks/01_ioc_batch_enrichment.py`, attach any DBR 13.3+ cluster,
   fill the widgets, run. The notebooks import `src/` and `vendor/` from the
   Git folder — nothing to install.

## 2. Wheel for jobs/clusters (no Git folder)

```bash
make wheel   # builds dist/kyberis_databricks-<version>-py3-none-any.whl
```

The wheel contains both `kyberis_databricks` and the vendored `kyberis_core`.
Upload it as a job/cluster library or to a UC volume, then
`%pip install /Volumes/.../kyberis_databricks-<version>-py3-none-any.whl`.

## 3. Databricks App

The repo root is the app source root (`app.yaml` lives there).

```bash
# one-time: create the app
databricks apps create kyberis-threat-intelligence

# add the two secret resources the app expects (see credentials.md):
#   kyberis-api-key-id     -> secret scope kyberis, key kyberis-api-key-id
#   kyberis-api-key-secret -> secret scope kyberis, key kyberis-api-key-secret
# (Compute → Apps → kyberis-threat-intelligence → Edit → Resources)

# deploy from a workspace copy of this repo
databricks sync . /Workspace/Users/<you>/kyberis-databricks
databricks apps deploy kyberis-threat-intelligence \
  --source-code-path /Workspace/Users/<you>/kyberis-databricks
```

Grant analysts **Can use** on the app (Permissions tab). The app's service
principal needs **READ** on the secret scope — Databricks configures that
automatically when the secret resources are added.

### Upgrading

Pull the Git folder (or re-run `databricks sync` + `deploy`). Version is
tracked in `pyproject.toml` / `kyberis_databricks.__version__`.

## Local development

```bash
make test                      # hermetic pytest suite
uv run --group dev --with 'streamlit>=1.38,<2' \
  streamlit run app/app.py     # run the app locally
```

Export `KYBERIS_API_KEY_ID`, `KYBERIS_API_KEY_SECRET`, and optionally
`KYBERIS_API_BASE_URL` before running the app locally.
