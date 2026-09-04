from __future__ import annotations

import pytest
from conftest import token_body
from kyberis_databricks.auth import (
    BearerTokenSession,
    KyberisAuthError,
    KyberisCredentials,
    base_url_from_env,
    load_credentials_from_env,
    load_credentials_from_secrets,
)


class TestCredentials:
    def test_api_key_header(self):
        creds = KyberisCredentials(key_id="kid", secret="sec")
        assert creds.api_key_header == "ApiKey kid:sec"

    def test_empty_parts_rejected(self):
        with pytest.raises(KyberisAuthError):
            KyberisCredentials(key_id="kid", secret=" ")
        with pytest.raises(KyberisAuthError):
            KyberisCredentials(key_id="", secret="sec")

    def test_repr_and_str_never_contain_secret(self):
        creds = KyberisCredentials(key_id="kid", secret="super-secret-value")
        assert "super-secret-value" not in repr(creds)
        assert "super-secret-value" not in str(creds)


class TestLoaders:
    def test_from_env(self):
        creds = load_credentials_from_env(
            {"KYBERIS_API_KEY_ID": " kid ", "KYBERIS_API_KEY_SECRET": "sec"}
        )
        assert creds.key_id == "kid"
        assert creds.secret == "sec"

    def test_from_env_missing_raises_without_leaking(self):
        with pytest.raises(KyberisAuthError) as excinfo:
            load_credentials_from_env({"KYBERIS_API_KEY_ID": "kid"})
        assert "KYBERIS_API_KEY_SECRET" in str(excinfo.value)

    def test_from_secrets(self):
        store = {("kyberis", "kyberis-api-key-id"): "kid", ("kyberis", "kyberis-api-key-secret"): "sec"}
        creds = load_credentials_from_secrets(lambda scope, key: store[(scope, key)], "kyberis")
        assert creds.api_key_header == "ApiKey kid:sec"

    def test_from_secrets_wraps_lookup_failure(self):
        def get_secret(scope, key):
            raise RuntimeError("Secret does not exist")

        with pytest.raises(KyberisAuthError) as excinfo:
            load_credentials_from_secrets(get_secret, "kyberis")
        assert "kyberis" in str(excinfo.value)

    def test_from_secrets_requires_scope(self):
        with pytest.raises(KyberisAuthError):
            load_credentials_from_secrets(lambda scope, key: "x", " ")

    def test_base_url_default_and_override(self):
        assert base_url_from_env({}) == "https://api.kyberis.ai"
        assert base_url_from_env({"KYBERIS_API_BASE_URL": "https://api.example.test"}) == (
            "https://api.example.test"
        )


class TestBearerTokenSession:
    def _session(self, fake_client, fake_clock, **kwargs):
        creds = KyberisCredentials(key_id="kid", secret="sec")
        return BearerTokenSession(fake_client, creds, time_source=fake_clock, **kwargs)

    def test_mints_with_api_key_and_caches(self, fake_client, fake_clock):
        fake_client.enqueue(200, token_body("tok-1", expires_in=1800))
        session = self._session(fake_client, fake_clock)

        assert session.auth_header() == "Bearer tok-1"
        assert session.auth_header() == "Bearer tok-1"
        assert len(fake_client.calls) == 1
        call = fake_client.calls[0]
        assert call["endpoint"] == "/v2/auth/token"
        assert call["auth_header"] == "ApiKey kid:sec"

    def test_refreshes_inside_margin(self, fake_client, fake_clock):
        fake_client.enqueue(200, token_body("tok-1", expires_in=1800))
        fake_client.enqueue(200, token_body("tok-2", expires_in=1800))
        session = self._session(fake_client, fake_clock, refresh_margin_seconds=60)

        assert session.auth_header() == "Bearer tok-1"
        fake_clock.advance(1800 - 30)  # inside the 60s refresh margin
        assert session.auth_header() == "Bearer tok-2"

    def test_invalidate_forces_fresh_mint(self, fake_client, fake_clock):
        fake_client.enqueue(200, token_body("tok-1"))
        fake_client.enqueue(200, token_body("tok-2"))
        session = self._session(fake_client, fake_clock)

        assert session.auth_header() == "Bearer tok-1"
        session.invalidate()
        assert session.auth_header() == "Bearer tok-2"

    def test_rejected_key_raises_auth_error(self, fake_client, fake_clock):
        fake_client.enqueue(401, {"error": "Unauthorized"})
        session = self._session(fake_client, fake_clock)
        with pytest.raises(KyberisAuthError) as excinfo:
            session.auth_header()
        assert "401" in str(excinfo.value)
        assert "sec" not in str(excinfo.value).split("secret")[-1]  # never echoes the secret

    def test_malformed_mint_response_raises(self, fake_client, fake_clock):
        fake_client.enqueue(200, {"unexpected": True})
        session = self._session(fake_client, fake_clock)
        with pytest.raises(KyberisAuthError):
            session.auth_header()

    def test_missing_expires_in_raises(self, fake_client, fake_clock):
        body = token_body("tok-1")
        body["expires_in"] = 0
        fake_client.enqueue(200, body)
        session = self._session(fake_client, fake_clock)
        with pytest.raises(KyberisAuthError):
            session.auth_header()
