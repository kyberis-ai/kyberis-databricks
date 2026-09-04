"""agent_context construction.

Every ``POST /v2/*`` endpoint requires an ``agent_context`` describing why
the call is being made (objective, requested outcome, workflow stage, run and
step identifiers). This module builds one that passes the API's validation
rules so callers get a clear local error instead of an HTTP 422.
"""

from __future__ import annotations

import re
import uuid

# Mirrors the API's WorkflowStage enum.
WORKFLOW_STAGES = (
    "resolve",
    "evidence",
    "relationships",
    "assessment",
    "hunt",
    "hydrate",
    "batch",
    "finalize",
    "other",
)

_RUN_ID_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def new_run_id(prefix: str = "dbx") -> str:
    """A fresh run_id like ``dbx-1f2e3d4c5b6a`` (4-64 chars, safe alphabet)."""
    prefix = _RUN_ID_SAFE.sub("-", str(prefix or "dbx").strip()) or "dbx"
    return f"{prefix}-{uuid.uuid4().hex[:12]}"[:64]


def build_agent_context(
    objective: str,
    requested_outcome: str,
    *,
    workflow_stage: str = "batch",
    run_id: str | None = None,
    step_id: str = "databricks",
    parent_step_id: str | None = None,
    priority: str | None = None,
    tags: list[str] | None = None,
) -> dict:
    """Build a valid ``agent_context`` dict, raising ``ValueError`` early.

    Validation mirrors the API's AgentContext model: objective 8-280 chars,
    requested_outcome 3-280, run_id 4-64, step_id 1-64, workflow_stage from
    ``WORKFLOW_STAGES``, at most 12 tags.
    """
    objective = str(objective or "").strip()
    requested_outcome = str(requested_outcome or "").strip()
    stage = str(workflow_stage or "").strip()
    run_id = str(run_id or "").strip() or new_run_id()
    step_id = str(step_id or "").strip()

    if not 8 <= len(objective) <= 280:
        raise ValueError("agent_context.objective must be 8-280 characters")
    if not 3 <= len(requested_outcome) <= 280:
        raise ValueError("agent_context.requested_outcome must be 3-280 characters")
    if stage not in WORKFLOW_STAGES:
        raise ValueError(f"agent_context.workflow_stage must be one of {WORKFLOW_STAGES}")
    if not 4 <= len(run_id) <= 64:
        raise ValueError("agent_context.run_id must be 4-64 characters")
    if not 1 <= len(step_id) <= 64:
        raise ValueError("agent_context.step_id must be 1-64 characters")
    if priority is not None and priority not in ("low", "normal", "high", "urgent"):
        raise ValueError("agent_context.priority must be low, normal, high, or urgent")
    if tags is not None and len(tags) > 12:
        raise ValueError("agent_context.tags allows at most 12 entries")

    context: dict = {
        "objective": objective,
        "requested_outcome": requested_outcome,
        "workflow_stage": stage,
        "run_id": run_id,
        "step_id": step_id,
    }
    if parent_step_id:
        context["parent_step_id"] = str(parent_step_id)[:64]
    if priority is not None:
        context["priority"] = priority
    if tags:
        context["tags"] = [str(tag) for tag in tags]
    return context
