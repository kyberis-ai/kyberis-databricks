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


class RecordingSleep:
    """Captures the waits the retry path asks for, without performing them."""

    def __init__(self):
        self.waits: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.waits.append(float(seconds))


@pytest.fixture
def fake_client():
    return FakeClient()


@pytest.fixture
def no_sleep(monkeypatch):
    from kyberis_databricks import enrich

    recorder = RecordingSleep()
    monkeypatch.setattr(enrich, "_sleep", recorder)
    return recorder


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


# ---------------------------------------------------------------------------
# Response fixtures.
#
# These are transcribed from real production responses captured on 2026-09-10
# against api.kyberis.ai (/v2/entity-resolution/batch and /v2/assessments/batch),
# not invented from the docs. That distinction has mattered: three separate bugs
# reached production behind fixtures that asserted a shape the API does not send
# -- a plan-limit error_code, a 429 that was never exercised, and the
# resolution confidence field below. Trimmed for readability, but every key
# present here appears in the real body under that name, and no key here is
# absent from it.
#
# If the API changes shape, re-capture rather than hand-editing: a fixture that
# drifts from production turns the suite into a test of our assumptions.
# ---------------------------------------------------------------------------


def batch_body(items, *, stop_on_error=False):
    """The batch envelope, including the metadata block the API really sends."""
    return {
        "items": items,
        "metadata": {
            "total": len(items),
            "processed": len(items),
            "errors": sum(1 for item in items if item.get("status") != "ok"),
            "stop_on_error": stop_on_error,
        },
    }


def ok_resolution_item(index, canonical_id="cve--2024-3400", entity_type="cve",
                       canonical_name=None, confidence=1.0, query="CVE-2024-3400"):
    """A resolved entity-resolution item.

    Note `resolution_confidence`, not `confidence` -- the API has never sent a
    key called `confidence` here.
    """
    return {
        "index": index,
        "status": "ok",
        "result": {
            "input": query,
            "resolution": {
                "status": "resolved",
                "input_mode": "query",
                "entity_type": entity_type,
                "canonical_id": canonical_id,
                "canonical_name": canonical_name or canonical_id,
                "resolution_confidence": confidence,
                "candidates": [
                    {
                        "entity_type": entity_type,
                        "canonical_id": canonical_id,
                        "canonical_name": canonical_name or canonical_id,
                        "match_type": "exact",
                        "score": 1.0,
                        "matched_on": None,
                        "aliases": None,
                        "metadata": None,
                    }
                ],
            },
        },
        "error": None,
    }


def not_found_resolution_item(index, query="zzz-not-a-real-entity"):
    """An unresolvable query.

    The item status is **ok**, not error -- "we looked and found nothing" is a
    result, and only the nested resolution.status says so.
    """
    return {
        "index": index,
        "status": "ok",
        "result": {
            "input": query,
            "resolution": {
                "status": "not_found",
                "input_mode": "query",
                "entity_type": None,
                "canonical_id": None,
                "canonical_name": None,
                "resolution_confidence": 0.0,
                "candidates": [],
            },
        },
        "error": None,
    }


def ok_assessment_item(index, urgency="this_week", score=0.77, ioc="185.244.39.165"):
    """A completed IOC assessment.

    `ranking_score` is 0-1, not 0-100. `signals` repeats decision_urgency and
    ranking_score alongside its own fields, and the enrichment that gives the
    row its value sits in `metadata`, not in the scored fields.
    """
    return {
        "index": index,
        "status": "ok",
        "result": {
            "assessment_type": "ioc_assessment",
            "trace_id": "e39671fcd5fc462696669963a78a30ee",
            "input": {
                "threat": None, "cve": None, "actor": None, "ioc": ioc,
                "environment": None, "environment_context": None, "time_range": None,
            },
            "priority": {"decision_urgency": urgency, "ranking_score": score},
            "signals": {
                "decision_urgency": urgency,
                "environment_threat": "medium",
                "action_confidence": "medium",
                "ranking_score": score,
            },
            "confidence": 0.65,
            "rationale_codes": [
                "has_decision_urgency", "has_environment_threat",
                "has_action_confidence", "has_ranking_score",
            ],
            "resolution": {
                "status": "resolved",
                "input_mode": "query",
                "entity_type": "ip",
                "canonical_id": f"ip--{ioc}",
                "canonical_name": ioc,
                "resolution_confidence": 1.0,
                "candidates": [],
            },
            "recommended_actions": [
                "Prioritize detections for MITRE techniques: T1140, T1113, T1005.",
                "Correlate with malware families from MALPEDIA: S0543.",
            ],
            "caveats": [],
            "evidence_refs": [
                {"id": "S0543", "type": "cmdb_software"},
                {"id": ioc, "type": "ioc"},
            ],
            "metadata": {
                "degraded": False,
                "degraded_reasons": None,
                "detail_level": "standard",
                "ioc_enriched": True,
                "ioc_lookup_status": "applied",
                "ioc_state": "NEW",
                "attribution_count": 4,
                "attributions": ["Molerats", "Molerats - G0021", "S0543", "DCSO"],
                "ioc_mitre_technique_count": 10,
                "ioc_mitre_techniques": ["T1140", "T1113", "T1005"],
                "target_industries": ["Bank", "Journalist"],
                "correlated_ioc_count": 0,
                "context_applied": False,
            },
        },
        "error": None,
    }


def error_item(index, message="entity_not_resolved", status_code=400):
    """A genuine per-item failure.

    `result` is null and the detail is under `error`, whose own keys are
    `status_code` and `error` -- there is no `reason` key, and no `message`.
    Rarer than it looks: the API answers even junk input with a scored `ok`
    item, so this is reached mainly by input it cannot parse as an entity.
    """
    return {
        "index": index,
        "status": "error",
        "result": None,
        "error": {
            "status_code": status_code,
            "error": message,
            "resolution": {
                "status": "not_found",
                "input_mode": "query",
                "entity_type": None,
                "canonical_id": None,
                "canonical_name": None,
                "resolution_confidence": 0.0,
                "candidates": [],
            },
        },
    }
