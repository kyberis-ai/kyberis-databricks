from __future__ import annotations

import json

import pytest
from conftest import batch_body, error_item, ok_assessment_item, ok_resolution_item
from kyberis_databricks.auth import KyberisAuthError
from kyberis_databricks.enrich import (
    BATCH_MAX_ITEMS,
    IOC_ASSESSMENT_COLUMNS,
    RESOLUTION_COLUMNS,
    KyberisPlanLimitError,
    assess_iocs,
    resolve_entities,
)

OBJECTIVE = "Enrich detection IOC table with Kyberis verdicts"


class TestResolveEntities:
    def test_ok_and_error_items_map_by_index(self, fake_client):
        fake_client.enqueue(
            200,
            batch_body(
                [
                    ok_resolution_item(0, canonical_id="ent-apt29", entity_type="actor"),
                    error_item(1, message="unresolvable"),
                ]
            ),
        )
        rows = resolve_entities(fake_client, "ApiKey k:s", ["APT29", "no-such-thing"], objective=OBJECTIVE)

        assert [row["query"] for row in rows] == ["APT29", "no-such-thing"]
        assert set(rows[0]) == set(RESOLUTION_COLUMNS)
        assert rows[0]["status"] == "ok"
        assert rows[0]["canonical_id"] == "ent-apt29"
        assert rows[0]["entity_type"] == "actor"
        assert rows[0]["confidence"] == pytest.approx(0.93)
        assert json.loads(rows[0]["raw"])["resolution"]["canonical_id"] == "ent-apt29"
        assert rows[1]["status"] == "error"
        assert "unresolvable" in rows[1]["message"]

    def test_payload_shape_and_agent_context(self, fake_client):
        fake_client.enqueue(200, batch_body([ok_resolution_item(0)]))
        resolve_entities(
            fake_client,
            "ApiKey k:s",
            ["1.2.3.4"],
            objective=OBJECTIVE,
            expected_types=["ip"],
            run_id="job-42",
        )

        call = fake_client.calls[0]
        assert call["endpoint"] == "/v2/entity-resolution/batch"
        payload = call["payload"]
        assert payload["items"] == [{"query": "1.2.3.4", "expected_types": ["ip"]}]
        assert payload["stop_on_error"] is False
        context = payload["agent_context"]
        assert context["objective"] == OBJECTIVE
        assert context["run_id"] == "job-42"
        assert context["workflow_stage"] == "batch"
        assert context["step_id"] == "resolve-batch-1"

    def test_dedups_and_chunks_inputs(self, fake_client):
        queries = [f"10.0.0.{i}" for i in range(60)] + ["10.0.0.0", "", None]
        fake_client.enqueue(200, batch_body([ok_resolution_item(i) for i in range(50)]))
        fake_client.enqueue(200, batch_body([ok_resolution_item(i) for i in range(10)]))

        rows = resolve_entities(fake_client, "ApiKey k:s", queries, objective=OBJECTIVE)

        assert len(rows) == 60  # deduped, empties dropped
        assert len(fake_client.calls) == 2
        assert len(fake_client.calls[0]["payload"]["items"]) == BATCH_MAX_ITEMS
        assert fake_client.calls[1]["payload"]["agent_context"]["step_id"] == "resolve-batch-2"
        # Same run_id across chunks of one logical run.
        run_ids = {call["payload"]["agent_context"]["run_id"] for call in fake_client.calls}
        assert len(run_ids) == 1

    def test_missing_item_becomes_error_row(self, fake_client):
        fake_client.enqueue(200, batch_body([ok_resolution_item(0)]))
        rows = resolve_entities(fake_client, "ApiKey k:s", ["a-query", "b-query"], objective=OBJECTIVE)
        assert rows[0]["status"] == "ok"
        assert rows[1]["status"] == "error"

    def test_callable_auth_provider(self, fake_client):
        fake_client.enqueue(200, batch_body([ok_resolution_item(0)]))
        resolve_entities(fake_client, lambda: "Bearer tok-9", ["1.2.3.4"], objective=OBJECTIVE)
        assert fake_client.calls[0]["auth_header"] == "Bearer tok-9"


class TestAssessIocs:
    def test_row_fields(self, fake_client):
        fake_client.enqueue(200, batch_body([ok_assessment_item(0)]))
        rows = assess_iocs(fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE)

        row = rows[0]
        assert set(row) == set(IOC_ASSESSMENT_COLUMNS)
        assert row["status"] == "ok"
        assert row["urgency"] == "act_now"
        assert row["score"] == pytest.approx(87.5)
        assert row["threat"] == "high"
        assert row["action_confidence"] == "medium"
        assert row["confidence"] == pytest.approx(0.8)
        assert row["entity"] == "1.2.3.4"
        assert row["entity_type"] == "ip"
        assert row["recommended_actions"] == ["block"]
        assert row["caveats"] == ["single-source"]
        assert row["degraded_reasons"] is None

    def test_item_shape(self, fake_client):
        fake_client.enqueue(200, batch_body([ok_assessment_item(0)]))
        assess_iocs(fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE)
        call = fake_client.calls[0]
        assert call["endpoint"] == "/v2/assessments/batch"
        assert call["payload"]["items"] == [
            {"assessment_type": "ioc_assessment", "payload": {"query": "1.2.3.4"}}
        ]


class TestFailureSemantics:
    def test_auth_rejection_raises(self, fake_client):
        fake_client.enqueue(401, {"error": "Unauthorized"})
        with pytest.raises(KyberisAuthError):
            assess_iocs(fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE)

    def test_plan_limit_annotates_remaining_and_raises(self, fake_client):
        iocs = [f"10.0.0.{i}" for i in range(60)]
        fake_client.enqueue(402, {"message": "Plan limit reached", "error_code": "plan_limit_exceeded"})

        with pytest.raises(KyberisPlanLimitError) as excinfo:
            assess_iocs(fake_client, "ApiKey k:s", iocs, objective=OBJECTIVE)

        rows = excinfo.value.rows
        assert len(rows) == 60
        assert all(row["status"] == "plan_limit" for row in rows)
        assert len(fake_client.calls) == 1  # second chunk never sent

    def test_plan_limited_403_is_not_auth_error(self, fake_client):
        fake_client.enqueue(403, {"message": "Denied", "error_code": "plan_limit_exceeded"})
        with pytest.raises(KyberisPlanLimitError):
            assess_iocs(fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE)

    def test_transport_error_annotates_chunk_and_continues(self, fake_client):
        queries = [f"10.0.0.{i}" for i in range(51)]
        fake_client.transport_error()
        fake_client.enqueue(200, batch_body([ok_resolution_item(0)]))

        rows = resolve_entities(fake_client, "ApiKey k:s", queries, objective=OBJECTIVE)

        assert [row["status"] for row in rows[:50]] == ["transport_error"] * 50
        assert rows[50]["status"] == "ok"

    def test_two_consecutive_transport_failures_stop_calling(self, fake_client):
        queries = [f"10.0.0.{i}" for i in range(150)]
        fake_client.transport_error()
        fake_client.transport_error()
        # No third response queued: a third API call would fail the test.

        rows = resolve_entities(fake_client, "ApiKey k:s", queries, objective=OBJECTIVE)

        assert len(rows) == 150
        assert all(row["status"] == "transport_error" for row in rows)
        assert len(fake_client.calls) == 2

    def test_http_error_annotates_chunk(self, fake_client):
        fake_client.enqueue(500, {"message": "boom"})
        rows = assess_iocs(fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE)
        assert rows[0]["status"] == "error"
        assert "boom" in rows[0]["message"]

    def test_empty_input_makes_no_calls(self, fake_client):
        assert resolve_entities(fake_client, "ApiKey k:s", [], objective=OBJECTIVE) == []
        assert fake_client.calls == []
