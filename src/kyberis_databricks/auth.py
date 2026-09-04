"""Credential loading and bearer token handling for Kyberis on Databricks.

``kyberis_core``'s client is auth-agnostic: it sends whatever Authorization
header the caller hands it and never mints or exchanges tokens. This module
owns the Databricks side of that contract:

- reading API key credentials from app environment variables (Databricks
  Apps secret resources) or a Databricks secret scope (notebooks/jobs), and
- exchanging them for short-lived bearer tokens via ``POST /v2/auth/token``
  so the long-lived API key secret is sent only on mint, not on every call.

Credentials never appear in ``repr()`` output, exception messages, or logs.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping

from kyberis_core import KyberisClient

ENV_KEY_ID = "KYBERIS_API_KEY_ID"
ENV_KEY_SECRET = "KYBERIS_API_KEY_SECRET"
ENV_BASE_URL = "KYBERIS_API_BASE_URL"

DEFAULT_BASE_URL = "https://api.kyberis.ai"
DEFAULT_SECRET_KEY_ID = "kyberis-api-key-id"
DEFAULT_SECRET_KEY_SECRET = "kyberis-api-key-secret"

TOKEN_ENDPOINT = "/v2/auth/token"

# Refresh this many seconds before the token's stated expiry so an in-flight
# batch never runs across the boundary with a just-expired token.
DEFAULT_REFRESH_MARGIN_SECONDS = 60


class KyberisAuthError(RuntimeError):
    """Credentials are missing, malformed, or rejected by the API."""


@dataclass(frozen=True, repr=False)
class KyberisCredentials:
    """A Kyberis API key pair. Never logged, never shown in repr."""

    key_id: str
    secret: str = field(hash=False)

    def __post_init__(self) -> None:
        if not str(self.key_id or "").strip() or not str(self.secret or "").strip():
            raise KyberisAuthError("Kyberis API key id and secret must both be non-empty")

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"KyberisCredentials(key_id={self.key_id!r}, secret=<redacted>)"

    @property
    def api_key_header(self) -> str:
        """Authorization header value for direct ApiKey auth."""
        return f"ApiKey {self.key_id}:{self.secret}"


def load_credentials_from_env(environ: Mapping[str, str] | None = None) -> KyberisCredentials:
    """Read credentials from environment variables.

    This is the Databricks Apps path: ``app.yaml`` maps the app's secret
    resources into ``KYBERIS_API_KEY_ID`` / ``KYBERIS_API_KEY_SECRET``.
    """
    env = os.environ if environ is None else environ
    key_id = str(env.get(ENV_KEY_ID) or "").strip()
    secret = str(env.get(ENV_KEY_SECRET) or "").strip()
    if not key_id or not secret:
        raise KyberisAuthError(
            f"{ENV_KEY_ID} and {ENV_KEY_SECRET} must both be set. In a Databricks App, "
            "map them from the app's secret resources in app.yaml; locally, export them."
        )
    return KyberisCredentials(key_id=key_id, secret=secret)


def load_credentials_from_secrets(
    get_secret: Callable[[str, str], str],
    scope: str,
    *,
    key_id_key: str = DEFAULT_SECRET_KEY_ID,
    secret_key: str = DEFAULT_SECRET_KEY_SECRET,
) -> KyberisCredentials:
    """Read credentials from a Databricks secret scope.

    This is the notebook/job path::

        creds = load_credentials_from_secrets(dbutils.secrets.get, "kyberis")

    ``get_secret`` is ``dbutils.secrets.get`` (or any ``(scope, key) -> str``
    callable), so this module never imports Databricks-only APIs and stays
    testable off-platform.
    """
    scope = str(scope or "").strip()
    if not scope:
        raise KyberisAuthError("A Databricks secret scope name is required")
    try:
        key_id = get_secret(scope, key_id_key)
        secret = get_secret(scope, secret_key)
    except Exception as error:
        raise KyberisAuthError(
            f"Could not read keys '{key_id_key}' / '{secret_key}' from secret scope "
            f"'{scope}'. Check the scope name and your CAN READ permission on it."
        ) from error
    return KyberisCredentials(key_id=str(key_id or "").strip(), secret=str(secret or "").strip())


def base_url_from_env(environ: Mapping[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    return str(env.get(ENV_BASE_URL) or "").strip() or DEFAULT_BASE_URL


class BearerTokenSession:
    """Mints and caches short-lived bearer tokens from an API key.

    ``auth_header()`` returns a ``Bearer <token>`` header value, minting a
    fresh token via ``POST /v2/auth/token`` only when the cached one is
    missing or inside the refresh margin. Safe to share across threads.

    Prefer this over sending ``credentials.api_key_header`` on every request:
    the long-lived secret then only ever travels on the mint call, and each
    request carries a token that expires on its own within ~30 minutes.
    """

    def __init__(
        self,
        client: KyberisClient,
        credentials: KyberisCredentials,
        *,
        refresh_margin_seconds: int = DEFAULT_REFRESH_MARGIN_SECONDS,
        time_source: Callable[[], float] = time.time,
    ):
        self._client = client
        self._credentials = credentials
        self._refresh_margin = max(0, int(refresh_margin_seconds))
        self._time = time_source
        self._lock = threading.Lock()
        self._token: str | None = None
        self._expires_at: float = 0.0

    def auth_header(self) -> str:
        with self._lock:
            if self._token is None or self._time() >= self._expires_at - self._refresh_margin:
                self._mint()
            return f"Bearer {self._token}"

    def invalidate(self) -> None:
        """Drop the cached token so the next call mints a fresh one."""
        with self._lock:
            self._token = None
            self._expires_at = 0.0

    def _mint(self) -> None:
        response = self._client.request_json(
            endpoint=TOKEN_ENDPOINT,
            method="POST",
            payload=None,
            auth_header=self._credentials.api_key_header,
        )
        if response.status_code in (401, 403):
            raise KyberisAuthError(
                f"The Kyberis API rejected the configured API key (HTTP {response.status_code}). "
                "Check the key id/secret and that the key has not been revoked."
            )
        body = response.body if isinstance(response.body, dict) else {}
        token = str(body.get("access_token") or "").strip()
        if response.status_code != 200 or not token:
            code = str(body.get("error_code") or "").strip()
            detail = f" ({code})" if code else ""
            raise KyberisAuthError(
                f"Token mint failed with HTTP {response.status_code}{detail}"
            )
        try:
            expires_in = int(body.get("expires_in") or 0)
        except (TypeError, ValueError):
            expires_in = 0
        if expires_in <= 0:
            raise KyberisAuthError("Token mint response is missing a valid expires_in")
        self._token = token
        self._expires_at = self._time() + expires_in
