# Contributing

Issues and pull requests are welcome — bug reports, docs corrections, and
notebook examples especially.

For anything security-related, please follow [SECURITY.md](SECURITY.md)
instead of opening a public issue.

## Development setup

The project uses [uv](https://docs.astral.sh/uv/). The helper package and the
vendored client are pure standard library, so there is nothing to install for
the test suite beyond pytest.

```bash
make test    # hermetic pytest suite — no network, no Databricks runtime
make wheel   # build dist/kyberis_databricks-<version>-py3-none-any.whl
```

To run the Streamlit app locally, export `KYBERIS_API_KEY_ID`,
`KYBERIS_API_KEY_SECRET`, and optionally `KYBERIS_API_BASE_URL`, then:

```bash
uv run --group dev --with 'streamlit>=1.38,<2' streamlit run app/app.py
```

CI runs the test suite on Python 3.10, 3.11, and 3.12 — 3.10 is the floor
because that is what Databricks Runtime 13.3 LTS ships, and 3.11 is the
Databricks Apps runtime.

## Guidelines

- **Keep the helper package dependency-free.** `src/kyberis_databricks` and
  `vendor/kyberis_core` are standard library only. That is what lets
  notebooks, jobs, and the app import them without cluster libraries or a
  package index. Streamlit is the app's dependency alone.
- **Keep tests hermetic.** The suite must never make a network call or
  require a Databricks runtime. Use the fakes in `tests/conftest.py`;
  Databricks APIs are always injected (for example, `dbutils.secrets.get` is
  passed in as a callable rather than imported).
- **Never log or render credentials.** New error paths must not put key
  material into messages, and new UI must not display it.
- **Do not edit `vendor/kyberis_core` by hand.** It is a vendored copy — see
  [vendor/README.md](vendor/README.md) for how to update it.
- **Every input yields exactly one row.** The batch helpers guarantee one
  output row per distinct input with a `status` column explaining what
  happened, even on partial failure. Preserve that contract; jobs depend on
  it.

## Pull requests

Run `make test` before opening a PR, and describe the Databricks surface your
change affects (notebooks/jobs, the app, or the wheel). Contributions are
accepted under the repository's [Apache 2.0 license](LICENSE).
