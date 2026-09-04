"""Kyberis threat intelligence helpers for Databricks.

Thin Databricks-specific layer over the vendored ``kyberis_core`` client:
credential loading (app environment variables or Databricks secret scopes),
short-lived bearer token handling, ``agent_context`` construction, and
batched enrichment helpers that return DataFrame-ready rows.
"""

from __future__ import annotations

from .auth import (
    DEFAULT_BASE_URL,
    BearerTokenSession,
    KyberisAuthError,
    KyberisCredentials,
    load_credentials_from_env,
    load_credentials_from_secrets,
)
from .context import WORKFLOW_STAGES, build_agent_context, new_run_id
from .enrich import (
    BATCH_MAX_ITEMS,
    IOC_ASSESSMENT_COLUMNS,
    RESOLUTION_COLUMNS,
    KyberisPlanLimitError,
    assess_iocs,
    resolve_entities,
)

__all__ = [
    "DEFAULT_BASE_URL",
    "BearerTokenSession",
    "KyberisAuthError",
    "KyberisCredentials",
    "load_credentials_from_env",
    "load_credentials_from_secrets",
    "WORKFLOW_STAGES",
    "build_agent_context",
    "new_run_id",
    "BATCH_MAX_ITEMS",
    "IOC_ASSESSMENT_COLUMNS",
    "RESOLUTION_COLUMNS",
    "KyberisPlanLimitError",
    "assess_iocs",
    "resolve_entities",
]

__version__ = "0.1.0"
