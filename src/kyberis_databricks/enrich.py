"""Batched enrichment helpers that return DataFrame-ready rows.

Each helper deduplicates its inputs, calls the matching Kyberis batch
endpoint in chunks of up to 50 items, and returns one flat dict per distinct
input with a fixed column set (missing values are ``None``), so results drop
straight into ``spark.createDataFrame(rows, schema)`` and Delta writes.

Failure semantics:

- 401/403 (bad credentials) raises :class:`KyberisAuthError` — the job is
  misconfigured and every further call would fail the same way.
- 402 / plan-limit responses stop further API calls; the remaining rows are
  annotated ``status="plan_limit"`` and :class:`KyberisPlanLimitError` is
  raised with the completed rows attached as ``error.rows``.
- Transport failures annotate the chunk ``status="transport_error"``; after
  two consecutive failing chunks no further calls are made.
- Any other HTTP error annotates the chunk ``status="error"``.

So apart from configuration problems, every input always yields exactly one
row whose ``status`` says what happened — batch jobs never lose partial work.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Iterable, Union

from kyberis_core import KyberisClient, KyberisClientError

from .auth import KyberisAuthError
from .context import build_agent_context, new_run_id

BATCH_MAX_ITEMS = 50

# Consecutive whole-chunk transport failures before we stop calling the API
# (keeps a dead network from adding retry latency to every remaining chunk).
_TRANSPORT_FAILURE_LIMIT = 2

ENTITY_RESOLUTION_BATCH_ENDPOINT = "/v2/entity-resolution/batch"
ASSESSMENTS_BATCH_ENDPOINT = "/v2/assessments/batch"

DEFAULT_RESOLVE_OUTCOME = "Canonical entity id, type, and confidence per input"
DEFAULT_ASSESS_OUTCOME = "Per-indicator verdict, score, and context fields"

RESOLUTION_COLUMNS = (
    "query",
    "status",
    "message",
    "resolution_status",
    "canonical_id",
    "canonical_name",
    "entity_type",
    "confidence",
    "raw",
)

IOC_ASSESSMENT_COLUMNS = (
    "ioc",
    "status",
    "message",
    "urgency",
    "score",
    "threat",
    "action_confidence",
    "confidence",
    "resolution_status",
    "entity",
    "entity_type",
    "recommended_actions",
    "caveats",
    "degraded_reasons",
    "raw",
)

AuthProvider = Union[str, Callable[[], str]]


class KyberisPlanLimitError(RuntimeError):
    """Plan/credit limit reached. ``rows`` holds every row produced so far
    (completed enrichments plus ``status="plan_limit"`` annotations)."""

    def __init__(self, message: str, rows: list[dict]):
        super().__init__(message)
        self.rows = rows


def resolve_entities(
    client: KyberisClient,
    auth: AuthProvider,
    queries: Iterable[str],
    *,
    objective: str,
    requested_outcome: str = DEFAULT_RESOLVE_OUTCOME,
    expected_types: list[str] | None = None,
    run_id: str | None = None,
    stop_on_error: bool = False,
) -> list[dict]:
    """Resolve raw indicators/names into canonical Kyberis entities.

    Returns one row per distinct non-empty query, columns
    :data:`RESOLUTION_COLUMNS`.
    """

    def make_item(value: str) -> dict:
        item: dict = {"query": value}
        if expected_types:
            item["expected_types"] = list(expected_types)
        return item

    def row_from_item(value: str, item: dict) -> dict:
        row = _empty_row(RESOLUTION_COLUMNS, "query", value)
        status = str(item.get("status") or "").strip().lower()
        if status != "ok":
            error = item.get("error") if isinstance(item.get("error"), dict) else {}
            row["status"] = "error"
            row["message"] = _error_message(error, "Kyberis returned no result for this query")
            row["raw"] = _dump(error or item)
            return row
        result = item.get("result") if isinstance(item.get("result"), dict) else {}
        resolution = result.get("resolution") if isinstance(result.get("resolution"), dict) else {}
        row["status"] = "ok"
        row["resolution_status"] = _text(resolution.get("status"))
        row["canonical_id"] = _text(resolution.get("canonical_id"))
        row["canonical_name"] = _text(resolution.get("canonical_name"))
        row["entity_type"] = _text(resolution.get("entity_type"))
        row["confidence"] = _number(resolution.get("confidence"))
        row["raw"] = _dump(result)
        return row

    return _run_batched(
        client,
        auth,
        queries,
        endpoint=ENTITY_RESOLUTION_BATCH_ENDPOINT,
        make_item=make_item,
        row_from_item=row_from_item,
        columns=RESOLUTION_COLUMNS,
        value_column="query",
        objective=objective,
        requested_outcome=requested_outcome,
        run_id=run_id,
        step_prefix="resolve",
        stop_on_error=stop_on_error,
    )


def assess_iocs(
    client: KyberisClient,
    auth: AuthProvider,
    iocs: Iterable[str],
    *,
    objective: str,
    requested_outcome: str = DEFAULT_ASSESS_OUTCOME,
    run_id: str | None = None,
    stop_on_error: bool = False,
) -> list[dict]:
    """Assess a bounded list of IOCs (IPs, domains, URLs, hashes, emails).

    Returns one row per distinct non-empty IOC, columns
    :data:`IOC_ASSESSMENT_COLUMNS`.
    """

    def make_item(value: str) -> dict:
        return {"assessment_type": "ioc_assessment", "payload": {"query": value}}

    def row_from_item(value: str, item: dict) -> dict:
        row = _empty_row(IOC_ASSESSMENT_COLUMNS, "ioc", value)
        status = str(item.get("status") or "").strip().lower()
        if status != "ok":
            error = item.get("error") if isinstance(item.get("error"), dict) else {}
            row["status"] = "error"
            row["message"] = _error_message(error, "Kyberis returned no result for this indicator")
            row["raw"] = _dump(error or item)
            return row
        result = item.get("result") if isinstance(item.get("result"), dict) else {}
        priority = result.get("priority") if isinstance(result.get("priority"), dict) else {}
        signals = result.get("signals") if isinstance(result.get("signals"), dict) else {}
        resolution = result.get("resolution") if isinstance(result.get("resolution"), dict) else {}
        metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
        row["status"] = "ok"
        row["urgency"] = _text(priority.get("decision_urgency"))
        row["score"] = _number(priority.get("ranking_score", signals.get("ranking_score")))
        row["threat"] = _text(signals.get("environment_threat"))
        row["action_confidence"] = _text(signals.get("action_confidence"))
        row["confidence"] = _number(result.get("confidence"))
        row["resolution_status"] = _text(resolution.get("status"))
        row["entity"] = _text(resolution.get("canonical_name") or resolution.get("canonical_id"))
        row["entity_type"] = _text(resolution.get("entity_type"))
        row["recommended_actions"] = _string_list(result.get("recommended_actions"))
        row["caveats"] = _string_list(result.get("caveats"))
        row["degraded_reasons"] = (
            _string_list(metadata.get("degraded_reasons")) if metadata.get("degraded") else None
        )
        row["raw"] = _dump(result)
        return row

    return _run_batched(
        client,
        auth,
        iocs,
        endpoint=ASSESSMENTS_BATCH_ENDPOINT,
        make_item=make_item,
        row_from_item=row_from_item,
        columns=IOC_ASSESSMENT_COLUMNS,
        value_column="ioc",
        objective=objective,
        requested_outcome=requested_outcome,
        run_id=run_id,
        step_prefix="assess",
        stop_on_error=stop_on_error,
    )


def _run_batched(
    client: KyberisClient,
    auth: AuthProvider,
    values: Iterable[str],
    *,
    endpoint: str,
    make_item: Callable[[str], dict],
    row_from_item: Callable[[str, dict], dict],
    columns: tuple[str, ...],
    value_column: str,
    objective: str,
    requested_outcome: str,
    run_id: str | None,
    step_prefix: str,
    stop_on_error: bool,
) -> list[dict]:
    pending: list[str] = []
    seen: set[str] = set()
    for value in values:
        value = str(value or "").strip()
        if value and value not in seen:
            seen.add(value)
            pending.append(value)

    run_id = run_id or new_run_id()
    rows: list[dict] = []
    transport_failures = 0
    stopped: tuple[str, str] | None = None

    for chunk_index, start in enumerate(range(0, len(pending), BATCH_MAX_ITEMS), start=1):
        chunk = pending[start : start + BATCH_MAX_ITEMS]

        if stopped is not None:
            rows.extend(_annotate(columns, value_column, chunk, *stopped))
            continue

        payload = {
            "agent_context": build_agent_context(
                objective,
                requested_outcome,
                workflow_stage="batch",
                run_id=run_id,
                step_id=f"{step_prefix}-batch-{chunk_index}",
            ),
            "items": [make_item(value) for value in chunk],
            "stop_on_error": stop_on_error,
        }

        try:
            response = client.request_json(
                endpoint=endpoint,
                method="POST",
                payload=payload,
                auth_header=_auth_header(auth),
            )
        except KyberisClientError as error:
            transport_failures += 1
            message = f"Kyberis API unreachable: {error}"
            if transport_failures >= _TRANSPORT_FAILURE_LIMIT:
                stopped = ("transport_error", message)
            rows.extend(_annotate(columns, value_column, chunk, "transport_error", message))
            continue

        transport_failures = 0
        body = response.body if isinstance(response.body, dict) else {}

        # 402 is the credit/billing precheck; 403 doubles as a plan-capability
        # denial (error_code plan_limit_exceeded) — only a plain 403 means bad
        # credentials.
        plan_limited = response.status_code == 402 or (
            response.status_code == 403
            and "plan_limit" in str(body.get("error_code") or body.get("message") or "")
        )
        if plan_limited:
            message = _error_message(body, "Kyberis plan limit reached") + (
                f" (HTTP {response.status_code})"
            )
            rows.extend(_annotate(columns, value_column, chunk, "plan_limit", message))
            for later_start in range(start + BATCH_MAX_ITEMS, len(pending), BATCH_MAX_ITEMS):
                rows.extend(
                    _annotate(
                        columns,
                        value_column,
                        pending[later_start : later_start + BATCH_MAX_ITEMS],
                        "plan_limit",
                        message,
                    )
                )
            raise KyberisPlanLimitError(message, rows)

        if response.status_code in (401, 403):
            raise KyberisAuthError(
                "The Kyberis API rejected the configured credentials "
                f"(HTTP {response.status_code}). Check the API key in your "
                "Databricks secret scope / app resources."
            )

        if response.status_code != 200 or not isinstance(response.body, dict):
            message = _error_message(
                response.body, f"Kyberis API error (HTTP {response.status_code})"
            )
            rows.extend(_annotate(columns, value_column, chunk, "error", message))
            continue

        # Items echo their request position as "index"; map by that rather
        # than list order so a short/partial items list can't shift results
        # onto the wrong input.
        by_index: dict[int, dict] = {}
        items = body.get("items")
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                try:
                    by_index[int(item.get("index"))] = item
                except (TypeError, ValueError):
                    pass
        for index, value in enumerate(chunk):
            rows.append(row_from_item(value, by_index.get(index, {})))

    return rows


def _auth_header(auth: AuthProvider) -> str:
    return auth() if callable(auth) else str(auth)


def _annotate(
    columns: tuple[str, ...], value_column: str, values: list[str], status: str, message: str
) -> list[dict]:
    rows = []
    for value in values:
        row = _empty_row(columns, value_column, value)
        row["status"] = status
        row["message"] = message
        rows.append(row)
    return rows


def _empty_row(columns: tuple[str, ...], value_column: str, value: str) -> dict:
    row = {column: None for column in columns}
    row[value_column] = value
    return row


def _error_message(body: Any, fallback: str) -> str:
    # Top-level errors carry message/error_code/reason; per-item errors are
    # not normalized and usually carry error (+ sometimes reason).
    if isinstance(body, dict):
        message = str(body.get("message") or body.get("error") or body.get("detail") or "").strip()
        if message:
            code = str(body.get("error_code") or body.get("reason") or "").strip()
            return f"{message} ({code})" if code and code != message else message
    return fallback


def _text(value: Any) -> str | None:
    text = str(value if value is not None else "").strip()
    return text or None


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _string_list(value: Any) -> list[str] | None:
    if isinstance(value, list) and value:
        return [str(entry) for entry in value]
    return None


def _dump(value: Any) -> str | None:
    if not value:
        return None
    try:
        return json.dumps(value, separators=(",", ":"), sort_keys=True, default=str)
    except (TypeError, ValueError):
        return None
