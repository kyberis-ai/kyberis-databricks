# Security policy

## Reporting a vulnerability

Report security issues in this integration privately to
**security@kyberis.ai**. Please do not open a public GitHub issue for a
suspected vulnerability.

Include what you need to describe the problem — affected file or endpoint,
reproduction steps, and impact. We acknowledge reports within three business
days and will keep you updated until the issue is resolved.

This policy covers the code in this repository. For vulnerabilities in the
Kyberis platform or API itself, use the same address.

## Scope and threat model

This integration is a client: it reads a Kyberis API key from Databricks
secret storage, exchanges it for a short-lived bearer token, and makes
outbound HTTPS calls to the Kyberis API. It exposes no network listeners and
Kyberis never calls into your workspace.

The security properties it is designed to hold, and which are worth reporting
if you can break them:

- **The API key never leaves secret storage.** It is read from a Databricks
  secret scope (`dbutils.secrets.get`) or from app environment variables
  mapped from app secret resources — never from notebooks, widgets, job
  parameters, cluster environment variables, or files in this repo.
- **Credentials never reach output.** `KyberisCredentials` redacts the secret
  from `repr()`, and no exception message raised by this code includes
  credential material.
- **The long-lived secret travels only on token mint.** Every other request
  carries a bearer token with a ≤30 minute lifetime.
- **TLS verification is always on.** The client uses `urllib` with system CA
  trust; there is no option here to disable verification or use plain HTTP.
- **Only one destination.** Requests go to `api.kyberis.ai` (or the
  `KYBERIS_API_BASE_URL` you configure) and nowhere else.

See [docs/privacy.md](docs/privacy.md) for exactly what data leaves a
workspace, and [docs/credentials.md](docs/credentials.md) for credential
handling and rotation.

## Out of scope

- Findings that require an attacker to already hold workspace admin rights or
  READ on your Kyberis secret scope.
- The vendored `kyberis_core` client's upstream design decisions — report
  those to the same address and we will route them to the client's
  maintainers.
