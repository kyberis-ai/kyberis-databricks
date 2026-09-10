from __future__ import annotations

import json

import pytest
from conftest import batch_body, error_item, ok_assessment_item, ok_resolution_item
from kyberis_databricks.auth import KyberisAuthError
from kyberis_databricks.enrich import (
    BATCH_MAX_ITEMS,
    IOC_ASSESSMENT_COLUMNS,
    IOC_ASSESSMENT_DISPLAY_ORDER,
    RESOLUTION_COLUMNS,
    KyberisPlanLimitError,
    assess_iocs,
    display_order,
    resolve_entities,
)
from kyberis_databricks.enrich import (
    _RATE_LIMIT_DEFAULT_SLEEP_SECONDS,
    _RATE_LIMIT_MAX_SLEEP_SECONDS,
    _RATE_LIMIT_RETRY_LIMIT,
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
        assert row["degraded"] is False
        assert row["degraded_reasons"] is None

    def test_enrichment_metadata_surfaces(self, fake_client):
        """Attribution and MITRE data live in metadata, not the scored fields,
        and must reach their own columns rather than only the raw blob."""
        fake_client.enqueue(200, batch_body([ok_assessment_item(0)]))
        row = assess_iocs(fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE)[0]

        assert row["attributions"] == ["Molerats", "S0543"]
        assert row["mitre_techniques"] == ["T1566.001", "T1140"]
        assert row["target_industries"] == ["Bank"]
        assert row["ioc_state"] == "NEW"
        assert row["evidence_refs"] == ["S0543 (cmdb_software)", "1.2.3.4"]

    def test_degraded_reasons_not_gated_by_flag(self, fake_client):
        """Reasons must surface even when the flag is absent or false —
        gating them behind `degraded` silently drops them."""
        item = ok_assessment_item(0)
        item["result"]["metadata"] = {"degraded_reasons": ["partial source outage"]}
        fake_client.enqueue(200, batch_body([item]))
        row = assess_iocs(fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE)[0]

        assert row["degraded"] is None
        assert row["degraded_reasons"] == ["partial source outage"]

    def test_item_shape(self, fake_client):
        fake_client.enqueue(200, batch_body([ok_assessment_item(0)]))
        assess_iocs(fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE)
        call = fake_client.calls[0]
        assert call["endpoint"] == "/v2/assessments/batch"
        assert call["payload"]["items"] == [
            {
                "assessment_type": "ioc_assessment",
                "payload": {"query": "1.2.3.4", "options": {"detail_level": "standard"}},
            }
        ]

    def test_detail_level_can_be_omitted(self, fake_client):
        fake_client.enqueue(200, batch_body([ok_assessment_item(0)]))
        assess_iocs(
            fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE, detail_level=None
        )
        payload = fake_client.calls[0]["payload"]["items"][0]["payload"]
        assert payload == {"query": "1.2.3.4"}


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

    def test_batch_cap_reported_as_batch_limit_is_not_an_auth_error(self, fake_client):
        # The real API names a batch cap error_code=batch_limit_exceeded with
        # message=plan_limit_exceeded, and gives no max_items we can shrink to.
        fake_client.enqueue(
            403,
            {
                "error_code": "batch_limit_exceeded",
                "message": "plan_limit_exceeded",
                "reason": "batch_limit_exceeded",
                "plan_code": "dev",
            },
        )
        with pytest.raises(KyberisPlanLimitError):
            assess_iocs(fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE)

    def test_batch_cap_reshrinks_chunks_and_completes(self, fake_client):
        iocs = [f"10.0.0.{i}" for i in range(12)]
        # First call sends all 12 and is refused with the plan's real cap.
        fake_client.enqueue(
            403,
            {
                "error_code": "batch_limit_exceeded",
                "message": "plan_limit_exceeded",
                "max_items": 5,
                "requested_items": 12,
            },
        )
        # It should then re-send the same items in chunks of five: 5, 5, 2.
        fake_client.enqueue(200, batch_body([ok_assessment_item(i) for i in range(5)]))
        fake_client.enqueue(200, batch_body([ok_assessment_item(i) for i in range(5)]))
        fake_client.enqueue(200, batch_body([ok_assessment_item(i) for i in range(2)]))

        rows = assess_iocs(fake_client, "ApiKey k:s", iocs, objective=OBJECTIVE)

        assert len(rows) == 12
        assert all(row["status"] == "ok" for row in rows)
        sent = [len(call["payload"]["items"]) for call in fake_client.calls]
        assert sent == [12, 5, 5, 2]
        # No input is dropped or duplicated by the re-chunking.
        assert [row["ioc"] for row in rows] == iocs

    def test_rate_limited_chunk_waits_and_is_re_sent_not_dropped(self, fake_client, no_sleep):
        # The real 429 body: reason names the condition, message reuses the
        # same "plan_limit_exceeded" marker a genuine plan denial sends.
        iocs = [f"10.0.0.{i}" for i in range(10)]
        fake_client.enqueue(
            429,
            {
                "error": "plan_limit_exceeded",
                "message": "plan_limit_exceeded",
                "reason": "rate_limit_exceeded",
                "plan_code": "dev",
                "limit": 10,
                "window_seconds": 60,
                "retry_after_seconds": 53,
            },
        )
        fake_client.enqueue(200, batch_body([ok_assessment_item(i) for i in range(10)]))

        rows = assess_iocs(fake_client, "ApiKey k:s", iocs, objective=OBJECTIVE, run_id="job-1")

        # Every input still enriched: the throttled chunk was re-sent, not consumed.
        assert len(rows) == 10
        assert all(row["status"] == "ok" for row in rows)
        assert [row["ioc"] for row in rows] == iocs
        # The retry carries exactly the items the refused request carried.
        sent = [
            [item["payload"]["query"] for item in call["payload"]["items"]]
            for call in fake_client.calls
        ]
        assert sent == [iocs, iocs]
        # It waited exactly as long as the API said, with no backoff curve of its own.
        assert no_sleep.waits == [53.0]

    def test_rate_limit_is_not_treated_as_a_plan_denial(self, fake_client, no_sleep):
        # message="plan_limit_exceeded" would match the plan-limit marker scan;
        # only the status code separates a throttle from a real denial, and a
        # throttle must not raise.
        fake_client.enqueue(429, {"message": "plan_limit_exceeded", "retry_after_seconds": 1})
        fake_client.enqueue(200, batch_body([ok_assessment_item(0)]))

        rows = assess_iocs(fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE)

        assert [row["status"] for row in rows] == ["ok"]

    def test_persistent_rate_limit_stops_calling_and_annotates_the_rest(self, fake_client, no_sleep):
        # 60 inputs is two chunks: 50 then 10.
        iocs = [f"10.0.0.{i}" for i in range(60)]
        throttled = {"message": "plan_limit_exceeded", "reason": "rate_limit_exceeded",
                     "retry_after_seconds": 60}
        # The first chunk never clears: the initial call plus the whole budget.
        for _ in range(_RATE_LIMIT_RETRY_LIMIT + 1):
            fake_client.enqueue(429, throttled)

        rows = assess_iocs(fake_client, "ApiKey k:s", iocs, objective=OBJECTIVE)

        # Bounded, and it stops calling: the second chunk is annotated without
        # another request rather than hammering a limit that is not clearing.
        assert len(fake_client.calls) == _RATE_LIMIT_RETRY_LIMIT + 1
        assert len(no_sleep.waits) == _RATE_LIMIT_RETRY_LIMIT
        # Still exactly one row per input — nothing is silently lost.
        assert len(rows) == 60
        assert [row["ioc"] for row in rows] == iocs
        assert all(row["status"] == "rate_limited" for row in rows)
        assert "rate_limit_exceeded" in rows[0]["message"]

    def test_retry_after_is_clamped_and_defaulted(self, fake_client, no_sleep):
        # A missing retry_after falls back to the window, then to a default;
        # an absurd one is capped so a bad field cannot hang a job.
        for body in ({"window_seconds": 60}, {}, {"retry_after_seconds": 99999}):
            fake_client.enqueue(429, body)
            fake_client.enqueue(200, batch_body([ok_assessment_item(0)]))
            assess_iocs(fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE)

        assert no_sleep.waits == [60.0, _RATE_LIMIT_DEFAULT_SLEEP_SECONDS,
                                  _RATE_LIMIT_MAX_SLEEP_SECONDS]

    def test_rate_limit_retry_budget_resets_between_chunks(self, fake_client, no_sleep):
        # A throttle on one chunk must not count against a later one, or a long
        # run would die early on a few scattered 429s spread across many chunks.
        iocs = [f"10.0.0.{i}" for i in range(12)]
        throttled = {"message": "plan_limit_exceeded", "retry_after_seconds": 5}
        # Shrink to chunks of five, then throttle each chunk once.
        fake_client.enqueue(403, {"error_code": "batch_limit_exceeded",
                                  "message": "plan_limit_exceeded", "max_items": 5})
        for size in (5, 5, 2):
            fake_client.enqueue(429, throttled)
            fake_client.enqueue(200, batch_body([ok_assessment_item(i) for i in range(size)]))

        rows = assess_iocs(fake_client, "ApiKey k:s", iocs, objective=OBJECTIVE)

        assert len(rows) == 12
        assert all(row["status"] == "ok" for row in rows)
        assert [row["ioc"] for row in rows] == iocs
        # Three separate one-wait recoveries, none inheriting the previous streak.
        assert no_sleep.waits == [5.0, 5.0, 5.0]
        sent = [len(call["payload"]["items"]) for call in fake_client.calls]
        assert sent == [12, 5, 5, 5, 5, 2, 2]

    def test_auth_error_includes_the_api_detail(self, fake_client):
        fake_client.enqueue(401, {"message": "bad key", "error_code": "unauthorized"})
        with pytest.raises(KyberisAuthError) as excinfo:
            assess_iocs(fake_client, "ApiKey k:s", ["1.2.3.4"], objective=OBJECTIVE)
        assert "bad key" in str(excinfo.value)

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


class TestDisplayOrder:
    """The display order is what decides which columns fall off the right edge
    of a 20-column grid, so it has to stay complete and lossless."""

    def test_covers_every_display_column_exactly_once(self):
        displayed = [column for column in IOC_ASSESSMENT_COLUMNS if column != "raw"]
        assert sorted(IOC_ASSESSMENT_DISPLAY_ORDER) == sorted(displayed)
        assert len(set(IOC_ASSESSMENT_DISPLAY_ORDER)) == len(IOC_ASSESSMENT_DISPLAY_ORDER)

    def test_reorders_without_dropping_or_inventing(self):
        displayed = [column for column in IOC_ASSESSMENT_COLUMNS if column != "raw"]
        ordered = display_order(displayed)
        assert sorted(ordered) == sorted(displayed)
        assert ordered == list(IOC_ASSESSMENT_DISPLAY_ORDER)

    def test_verdict_and_intelligence_lead_the_diagnostics(self):
        # The point of the order: an analyst sees the indicator, the verdict and
        # the evidence for it before any plumbing column.
        ordered = display_order([c for c in IOC_ASSESSMENT_COLUMNS if c != "raw"])
        assert ordered[:8] == [
            "ioc", "urgency", "score", "threat",
            "attributions", "mitre_techniques", "target_industries", "recommended_actions",
        ]
        for plumbing in ("resolution_status", "entity_type", "degraded_reasons"):
            assert ordered.index(plumbing) > ordered.index("recommended_actions")

    def test_unregistered_columns_survive_at_the_end(self):
        # A column added to the row builder must still render without having to
        # be registered in the order first.
        assert display_order(["zz_new", "ioc", "score"]) == ["ioc", "score", "zz_new"]

    def test_missing_columns_are_not_conjured(self):
        assert display_order(["score", "ioc"]) == ["ioc", "score"]

    def test_is_idempotent(self):
        displayed = [column for column in IOC_ASSESSMENT_COLUMNS if column != "raw"]
        once = display_order(displayed)
        assert display_order(once) == once
