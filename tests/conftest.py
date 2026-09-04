"""Shared fakes. Tests are hermetic: no network, no Databricks runtime."""

from __future__ import annotations

import pytest
from kyberis_core import KyberisClientError
from kyberis_core.client import RequestResult


class FakeClient:
    """Stands in for kyberis_core.KyberisClient.

    Queue responses with ``enqueue``; every ``request_json`` call is recorded
    in ``calls`` (endpoint, method, payload, auth_header). A queued exception
    is raised instead of returned.
    """

    def __init__(self):
        self.calls: list[dict] = []
        self._responses: list[object] = []

    def enqueue(self, status_code: int | Exception, body=None):
        if isinstance(status_code, Exception):
            self._responses.append(status_code)
        else:
            self._responses.append(RequestResult(status_code=status_code, body=body))
        return self

    def transport_error(self, message="connection refused"):
        return self.enqueue(KyberisClientError(f"Failed to call Kyberis API: {message}"))

    def request_json(self, *, endpoint, method, payload, auth_header=None, extra_headers=None):
        self.calls.append(
            {
                "endpoint": endpoint,
                "method": method,
                "payload": payload,
                "auth_header": auth_header,
                "extra_headers": extra_headers,
            }
        )
        if not self._responses:
            raise AssertionError(f"FakeClient has no response queued for {endpoint}")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeClock:
    def __init__(self, now=1_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def fake_client():
    return FakeClient()


@pytest.fixture
def fake_clock():
    return FakeClock()


def token_body(token="tok-1", expires_in=1800):
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "issued_at": 0,
        "expires_at": expires_in,
        "principal_id": "principal-1",
        "scopes": ["read:resolution"],
        "audiences": ["kyberis-api"],
        "issuer": "kyberis",
    }


def batch_body(items):
    return {"items": items, "metadata": {}}


def ok_resolution_item(index, canonical_id="ent-1", entity_type="ip", confidence=0.93):
    return {
        "index": index,
        "status": "ok",
        "result": {
            "resolution": {
                "status": "resolved",
                "canonical_id": canonical_id,
                "canonical_name": canonical_id,
                "entity_type": entity_type,
                "confidence": confidence,
            }
        },
    }


def ok_assessment_item(index, urgency="act_now", score=87.5):
    return {
        "index": index,
        "status": "ok",
        "result": {
            "priority": {"decision_urgency": urgency, "ranking_score": score},
            "signals": {"environment_threat": "high", "action_confidence": "medium"},
            "confidence": 0.8,
            "resolution": {
                "status": "resolved",
                "canonical_id": "ioc-1",
                "canonical_name": "1.2.3.4",
                "entity_type": "ip",
            },
            "recommended_actions": ["block"],
            "caveats": ["single-source"],
            "metadata": {"degraded": False},
        },
    }


def error_item(index, message="unresolvable", code="not_found"):
    return {
        "index": index,
        "status": "error",
        "error": {"error": message, "reason": code},
    }
