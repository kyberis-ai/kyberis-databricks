from __future__ import annotations

import pytest
from kyberis_databricks.context import WORKFLOW_STAGES, build_agent_context, new_run_id


class TestNewRunId:
    def test_shape(self):
        run_id = new_run_id()
        assert run_id.startswith("dbx-")
        assert 4 <= len(run_id) <= 64

    def test_prefix_sanitized(self):
        assert new_run_id("my job!").startswith("my-job-")


class TestBuildAgentContext:
    def test_minimal(self):
        context = build_agent_context("Enrich IOC table", "Verdicts per IOC")
        assert context["objective"] == "Enrich IOC table"
        assert context["requested_outcome"] == "Verdicts per IOC"
        assert context["workflow_stage"] == "batch"
        assert 4 <= len(context["run_id"]) <= 64
        assert context["step_id"] == "databricks"
        assert "parent_step_id" not in context
        assert "priority" not in context
        assert "tags" not in context

    def test_all_fields(self):
        context = build_agent_context(
            "Enrich IOC table",
            "Verdicts per IOC",
            workflow_stage="assessment",
            run_id="job-123",
            step_id="chunk-2",
            parent_step_id="chunk-1",
            priority="high",
            tags=["databricks", "nightly"],
        )
        assert context["workflow_stage"] == "assessment"
        assert context["run_id"] == "job-123"
        assert context["parent_step_id"] == "chunk-1"
        assert context["priority"] == "high"
        assert context["tags"] == ["databricks", "nightly"]

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"objective": "short"},  # < 8 chars
            {"objective": "x" * 281},
            {"requested_outcome": "ab"},  # < 3 chars
            {"requested_outcome": "x" * 281},
            {"workflow_stage": "not-a-stage"},
            {"run_id": "abc"},  # < 4 chars
            {"run_id": "x" * 65},
            {"step_id": ""},
            {"priority": "asap"},
            {"tags": [str(i) for i in range(13)]},
        ],
    )
    def test_invalid_inputs_raise_value_error(self, kwargs):
        arguments = {"objective": "Enrich IOC table", "requested_outcome": "Verdicts per IOC"}
        arguments.update(kwargs)
        objective = arguments.pop("objective")
        requested_outcome = arguments.pop("requested_outcome")
        with pytest.raises(ValueError):
            build_agent_context(objective, requested_outcome, **arguments)

    def test_stages_match_known_apiv2_values(self):
        assert "batch" in WORKFLOW_STAGES
        assert "assessment" in WORKFLOW_STAGES
