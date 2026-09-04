from __future__ import annotations

from dataclasses import dataclass


# The prefix that ToolSpec endpoints are authored against (e.g. "/v2/entity-resolution").
# A deployment whose API is mounted elsewhere sets KyberisClientConfig.api_prefix to rewrite it.
DEFAULT_API_PREFIX = "/v2"


@dataclass(frozen=True)
class KyberisClientConfig:
    """Everything KyberisClient needs to reach the Kyberis API.

    This is the SDK's whole configuration surface. Each consumer builds one of
    these from its own settings/secrets store and hands it to KyberisClient;
    the client never reads env vars or files.
    """

    base_url: str
    api_prefix: str = DEFAULT_API_PREFIX
    timeout_seconds: int = 20
    max_retries: int = 2
