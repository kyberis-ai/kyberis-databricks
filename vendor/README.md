# Vendored libraries

`kyberis_core/` is a vendored copy of the shared Kyberis API client. It is
pure standard library with no runtime dependencies, which is what makes
vendoring safe: notebooks, jobs, and the Databricks App all import it without
a package index or a network fetch at deploy time, and the wheel built by
`make wheel` ships it alongside `kyberis_databricks`.

Keeping it here rather than as a dependency is deliberate — a Databricks Git
folder should be runnable the moment it is cloned into a workspace, with no
cluster libraries to install.

## Updating

Do not edit files in `kyberis_core/` directly; changes here are overwritten
on the next sync and diverge from the client every other Kyberis integration
uses. Fixes belong upstream in the client itself.

Maintainers with a checkout of the client repo alongside this one refresh the
copy with `make sync-vendor`, then review the diff, bump the version in
`pyproject.toml` and `src/kyberis_databricks/__init__.py`, and note the client
change in the commit message.

If you have found a bug in the vendored client, please
[open an issue](https://github.com/kyberis-ai/kyberis-databricks/issues) —
we will route it upstream.
