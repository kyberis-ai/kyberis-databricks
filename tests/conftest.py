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


# ---------------------------------------------------------------------------
# Intel search fixtures.
#
# Captured on 2026-09-11 from POST /v2/intel-search with the query the app's
# Intel search tab suggests ("ransomware targeting healthcare", 30-day window,
# max_results 20).
#
# /v2/intel-search was the one endpoint no fixture here had ever pinned, and
# the app read its capsule list as {"results": [...]}. It is {"items": [...]},
# so every intel search the app ran rendered "No intel capsules matched." The
# captured envelope keys are exactly
# ['items', 'max_results', 'metadata', 'query', 'status'], with no 'results'.
#
# Two properties of the real bodies that the schema alone does not convey, and
# that the rendering has to hold up against:
#
# - `claim_tags` is free text, not a slug vocabulary: values arrive as vendor
#   and agency names at mixed casing and full length ("beyondtrust",
#   "Carbon Black", "Department of Health and Human Services (HHS)").
# - `abstract_stub` can end mid-sentence, and well under the documented
#   320-character cap, so length does not tell you whether it was cut.
#
# Same rule as the batch fixtures above: if the API changes shape, re-capture
# rather than hand-editing a body to make a test pass.
# ---------------------------------------------------------------------------


def public_capsule():
    """A real captured capsule, verbatim.

    `abstract_stub` is the capsule's only prose -- there is no `summary` key,
    which the app's `result.get("summary")` fallback assumed there was. Note
    it ends mid-sentence: that is what the API sent, not a trim made here.
    """
    return {
        "report_id": 111737,
        "report_uuid": "df61b2af-701e-50ef-ae03-67923b26cd3d",
        "title": (
            "Medusa ransomware tallies hundreds of new victims, says updated "
            "advisory on group\u2019s tactics"
        ),
        "published_date": "2026-08-18",
        "source": "feed",
        "access_level": "public",
        "url": "https://cyberscoop.com/medusa-ransomware-tactics-cisa-advisory/",
        "access_hint": None,
        "canonical_entities": [],
        "claim_tags": [
            "beyondtrust",
            "Carbon Black",
            "Cybercrime",
            "Cybersecurity and Infrastructure Security Agency (CISA)",
            "Department of Health and Human Services (HHS)",
            "Federal Bureau of Investigation (FBI)",
        ],
        "abstract_stub": (
            "A US government advisory (CISA, FBI, HHS) details updated Medusa "
            "ransomware tactics. The group has added over 200 victims in the "
            "past year, bringing"
        ),
        "match_score": 0.08,
        "match_reasons": ["token_hits:1", "fresh_30d"],
    }


def off_topic_capsule():
    """The other real capsule from the same response.

    Kept because it is the honest face of this endpoint: a 0.08 match on
    "token_hits:1, fresh_30d" for a report about counterfeit installers, which
    is neither ransomware nor healthcare. Whatever the tab renders has to stay
    readable when the matches are this weak.
    """
    return {
        "report_id": 111945,
        "report_uuid": "18dfc7d7-2eb6-5841-a458-7940f37e523a",
        "title": (
            "Counterfeit installers to system compromise: Tracking a deceptive "
            "software download campaign"
        ),
        "published_date": "2026-09-01",
        "source": "feed",
        "access_level": "public",
        "url": (
            "https://www.microsoft.com/en-us/security/blog/2026/09/01/counterfeit-"
            "installers-system-compromise-tracking-deceptive-software-download-campaign/"
        ),
        "access_hint": None,
        "canonical_entities": [],
        "claim_tags": ["Malware"],
        "abstract_stub": (
            "A malware campaign, likely by the \"Silver Fox\" group, is targeting "
            "Chinese-speaking users with counterfeit software download websites. "
            "The sites impersonate popular vendors to distribute malicious "
            "installers that lead to"
        ),
        "match_score": 0.08,
        "match_reasons": ["token_hits:1", "fresh_30d"],
    }


def intel_entity(entity_type="actor", canonical_id="actor--medusa",
                 canonical_name="Medusa", confidence=0.85):
    """One canonical_entities pivot.

    Note `confidence` here, not `resolution_confidence` -- intel search scores
    how strongly the report is associated with the entity, which is a
    different measure from entity_resolution's match confidence, and the two
    endpoints do use different key names for it.
    """
    return {
        "entity_type": entity_type,
        "canonical_id": canonical_id,
        "canonical_name": canonical_name,
        "confidence": confidence,
    }


def capsule_with_entities():
    """A capsule carrying pivots. Derived from the schema, not captured.

    No captured response included a capsule with canonical_entities, so this
    body comes from the API's published openapi.json instead, and is validated
    against it mechanically: IntelSearchItem declares
    additionalProperties=false, and this passes that schema clean, so no key
    is invented and none required is missing.

    It exists so the pivot-rendering path is exercised rather than left
    silently dead. Replace it with a capture when one is available -- a schema
    says what is permitted, not what arrives.
    """
    capsule = public_capsule()
    capsule["canonical_entities"] = [
        intel_entity("actor", "actor--medusa", "Medusa", 0.85),
        intel_entity("malware", "malware--medusa-ransomware", "Medusa Ransomware", 0.75),
        intel_entity("cve", "cve--2024-57727", "CVE-2024-57727", 0.65),
    ]
    return capsule


def restricted_capsule():
    """A non-public capsule. Also schema-derived, not captured.

    Every capsule in the capture was access_level="public" with a live url, so
    the restricted branch (url null, access_hint naming the entitled path) had
    no capture to draw on. Validated against the published schema, same as
    capsule_with_entities above.
    """
    return {
        "report_id": 111650,
        "report_uuid": None,
        "title": "Customer incident review: ransomware attempt against regional hospital network",
        "published_date": "2026-08-14",
        "source": "manual",
        "access_level": "restricted",
        "url": None,
        "access_hint": "Restricted source; use entitled retrieval path.",
        "canonical_entities": [],
        "claim_tags": ["Cybercrime"],
        "abstract_stub": "Customer incident review: ransomware attempt against regional hospital network",
        "match_score": 0.41,
        "match_reasons": ["token_hits:2"],
    }


def intel_search_body(items=None, *, query="ransomware targeting healthcare",
                      max_results=20, truncated=False, warnings=None):
    """The captured envelope, including the metadata block it really sends."""
    items = [public_capsule(), off_topic_capsule()] if items is None else items
    return {
        "status": "ok" if items else "no_results",
        "query": query,
        "max_results": max_results,
        "items": items,
        "metadata": {
            "item_count": len(items),
            "truncated": truncated,
            "warnings": list(warnings or []),
        },
    }
