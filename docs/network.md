# Network requirements

## Egress

The integration makes outbound HTTPS calls **only** to the Kyberis API:

| Destination | Port | Purpose |
|---|---|---|
| `api.kyberis.ai` (or your `KYBERIS_API_BASE_URL`) | 443 | `POST /v2/auth/token` (token mint) and `/v2/*` enrichment endpoints |

No other hosts are contacted at runtime. There are no webhooks or inbound
connections; Kyberis never calls into your workspace.

- **Classic compute**: allow egress to `api.kyberis.ai:443` from cluster
  subnets (VPC/VNet firewall or egress appliance).
- **Serverless compute / Apps**: if your account uses serverless egress
  control, add `api.kyberis.ai` to the allowed destinations of the
  workspace's network policy.

## TLS

- HTTPS only. The client uses Python's standard `urllib` with system CA
  trust and certificate verification on; there is no option in this
  integration to disable verification or use plain http.
- If you route through a TLS-inspecting proxy, its CA must be in the
  cluster/app system trust store.

## Timeouts and retries

Requests time out after 20 seconds and retry HTTP 429/5xx up to 2 times
with short backoff (vendored client defaults). Batch helpers additionally
stop calling the API after two consecutive whole-batch transport failures
and annotate remaining rows `transport_error` instead of hanging a job on a
dead network.
