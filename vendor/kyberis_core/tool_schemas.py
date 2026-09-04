from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    endpoint: str
    method: str
    requires_agent_context_headers: bool = False


CLAIM_TYPES = (
    "active_exploitation",
    "sector_targeting",
    "actor_association",
    "campaign_association",
    "malware_association",
    "relevance_to_environment",
    "observed_in_the_wild",
)

ENTITY_TYPES = ("cve", "actor", "malware", "campaign", "ip", "domain", "url", "hash", "email")
RELATIONSHIP_TYPES = ("actor", "campaign", "malware", "sector", "ioc", "technique")
ASSESSMENT_TYPES = (
    "threat_assessment",
    "cve_assessment",
    "actor_assessment",
    "environment_assessment",
    "ioc_assessment",
)


_AGENT_CONTEXT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "objective": {"type": "string", "minLength": 8, "maxLength": 280},
        "requested_outcome": {"type": "string", "minLength": 3, "maxLength": 280},
        "workflow_stage": {
            "type": "string",
            "enum": ["resolve", "evidence", "relationships", "assessment", "hunt", "hydrate", "batch", "finalize", "other"],
        },
        "run_id": {"type": "string", "minLength": 4, "maxLength": 64},
        "step_id": {"type": "string", "minLength": 1, "maxLength": 64},
    },
    "required": ["objective", "requested_outcome", "workflow_stage", "run_id", "step_id"],
    "additionalProperties": True,
}


def _subject_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "entity_type": {"type": "string", "enum": list(ENTITY_TYPES)},
            "canonical_id": {"type": "string", "minLength": 1},
        },
        "required": ["entity_type", "canonical_id"],
        "additionalProperties": True,
    }


def _environment_context_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "sector": {"type": "string"},
            "regions": {"type": "array", "items": {"type": "string"}},
            "internet_exposure": {"type": "string", "enum": ["none", "low", "medium", "high"]},
            "critical_asset_exposure": {"type": "string", "enum": ["none", "low", "medium", "high"]},
            "control_maturity": {"type": "string", "enum": ["weak", "moderate", "strong"]},
            "externally_exposed_service_count": {"type": "integer", "minimum": 0, "maximum": 200000},
            "crown_jewel_asset_count": {"type": "integer", "minimum": 0, "maximum": 50000},
            "eol_asset_count": {"type": "integer", "minimum": 0, "maximum": 50000},
            "detection_coverage": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "mfa_enforced": {"type": "boolean"},
            "patch_latency_days": {"type": "integer", "minimum": 0, "maximum": 365},
        },
        "additionalProperties": False,
    }


def _assessment_payload_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "agent_context": _AGENT_CONTEXT_SCHEMA,
            "subject": _subject_schema(),
            "query": {"type": "string", "minLength": 1, "maxLength": 1024},
            "expected_types": {"type": "array", "items": {"type": "string", "enum": list(ENTITY_TYPES)}},
            "resolution": {"type": "object"},
            "context": {"type": "object"},
            "time_range": {"type": "object"},
            "options": {"type": "object"},
            "environment": {"type": "string"},
            "environment_context": _environment_context_schema(),
        },
        "additionalProperties": True,
    }


def _post_schema(additional: dict[str, Any]) -> dict[str, Any]:
    properties = {
        "agent_context": _AGENT_CONTEXT_SCHEMA,
        **additional,
    }
    return {
        "type": "object",
        "properties": properties,
        "required": ["agent_context"],
        "additionalProperties": True,
    }


THREAT_INVESTIGATION_GUIDE: dict[str, Any] = {
    "title": "Kyberis threat investigation guide",
    "default_workflow": [
        "Use intel_search first for broad/open-ended topic questions.",
        "Use entity_resolution for specific entities, aliases, observables, or ambiguous terms.",
        "If resolution.status is ambiguous, narrow expected_types or ask for disambiguation before proceeding.",
        "Use claim_evidence for claim-level substantiation such as active exploitation or sector targeting.",
        "Use relationships to pivot to related actors, campaigns, malware, sectors, IoCs, and CVE techniques.",
        "Use hunt_pivots when the agent needs ranked next investigative actions for a resolved subject or weak observation.",
        "Use a type-specific assessment tool when the entity type is known; use threat_assessment when type is unknown or mixed.",
        "Use entity_resolution_batch for bounded lists of entities and assessments_batch for bounded IOC/CVE/actor/environment assessment lists.",
        "For batch responses, HTTP 200 means the batch envelope was processed; inspect every item.status and item.error before summarizing.",
        "Hydrate important canonical entity IDs and evidence IDs before final synthesis.",
        "For HTTP error payloads, branch on error_code when present and preserve request_id, run_id, and step_id for debugging.",
        "Final output should separate evidence, confidence, caveats/degraded metadata, and next actions.",
    ],
    "subject_query_mode": {
        "rule": "For evidence, relationships, and assessment tools, provide exactly one of subject or query. hunt_pivots accepts a subject, observed telemetry, or both.",
        "subject": "Preferred after entity_resolution. Use {'entity_type': '<type>', 'canonical_id': '<id>'}.",
        "query": "Use for quick single-step calls when the tool should resolve internally.",
    },
    "claim_types": list(CLAIM_TYPES),
    "batch_guidance": [
        "Batch endpoints require top-level agent_context, 1-50 items, and optional stop_on_error (default false).",
        "For assessments_batch, each item has assessment_type and payload. Use assessment_type='ioc_assessment' for IOC lists.",
        "Top-level agent_context is propagated into item payloads by apiv2 when omitted.",
        "Use stop_on_error=false for mixed-quality IOC lists and retry failed 429/503/504 items individually or in smaller batches.",
    ],
    "claim_notes": {
        "sector_targeting": "Requires context.sector.",
        "confidence": "resolution_confidence is match confidence; assessment confidence is score certainty, not business impact by itself.",
        "errors": "Public API errors include error_code, message, status_code, request_id, run_id, and step_id when available.",
    },
    "playbooks": {
        "cve": [
            "Resolve with expected_types=['cve'].",
            "Call claim_evidence for active_exploitation.",
            "If sector or industry matters, call claim_evidence with claim_type='sector_targeting' and context.sector.",
            "Call relationships with actor/campaign/technique pivots.",
            "Call hunt_pivots when you need product exposure or exploit-behavior hunt actions for customer telemetry.",
            "Call cve_assessment with the canonical subject and relevant context.",
        ],
        "actor": [
            "Resolve aliases with expected_types=['actor'].",
            "Call claim_evidence for relevance_to_environment and observed_in_the_wild.",
            "Call relationships for campaign, malware, and technique pivots.",
            "Call hunt_pivots when the user asks what to hunt next for actor-linked behavior or weak observations.",
            "Call actor_assessment with the canonical subject.",
        ],
        "environment": [
            "Resolve the threat, CVE, actor, campaign, malware, or IOC if it is not already canonical.",
            "Build environment_context with sector, regions, exposure, control maturity, asset counts, detection coverage, MFA, or patch latency.",
            "Call environment_assessment with exactly one of subject or query plus environment_context.",
            "Use environment_threat, priority, confidence, caveats, and evidence_refs to explain why the subject is or is not relevant to the environment.",
        ],
        "ioc": [
            "Resolve the observable with expected_types matching ip/domain/url/hash/email.",
            "For bounded IOC lists, call assessments_batch with assessment_type='ioc_assessment' and one payload.query per IOC.",
            "Call claim_evidence for active_exploitation, actor_association, and campaign_association.",
            "Call relationships for actor/campaign/malware/technique pivots.",
            "Call ioc_assessment with the canonical subject.",
        ],
        "open_ended": [
            "Start with intel_search to retrieve recent bounded intel capsules.",
            "Use canonical_entities and claim_tags from results as pivots.",
            "Resolve selected pivots, then continue with evidence, relationships, and assessments.",
        ],
        "prioritization": [
            "Build environment context with products, vendors, industry, geography, and exposure.",
            "Call prioritize to rank signals for immediate attention.",
            "Call hunt_pivots when a top signal needs ranked customer-telemetry hunt actions.",
            "Investigate top-ranked signals with evidence, relationships, type-specific assessments, or assessments_batch for bounded shortlists.",
        ],
    },
}


def threat_investigation_guide(scenario: str | None = None) -> dict[str, Any]:
    requested = str(scenario or "").strip().lower()
    if requested and requested in THREAT_INVESTIGATION_GUIDE["playbooks"]:
        return {
            **THREAT_INVESTIGATION_GUIDE,
            "selected_scenario": requested,
            "selected_playbook": THREAT_INVESTIGATION_GUIDE["playbooks"][requested],
        }
    return THREAT_INVESTIGATION_GUIDE


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="threat_investigation_guide",
        description=(
            "Read this first when the agent needs to perform a threat investigation. "
            "Returns the recommended workflow: intel_search for broad questions; entity_resolution to canonicalize; "
            "claim_evidence for active_exploitation, sector_targeting, actor_association, campaign_association, "
            "malware_association, relevance_to_environment, and observed_in_the_wild; relationships for graph pivots; "
            "hunt_pivots for ranked next investigative actions; "
            "type-specific assessments for known CVE/actor/IOC subjects; threat_assessment for unknown or mixed inputs; "
            "entity_resolution_batch and assessments_batch for bounded high-throughput lists where every item result must be inspected; "
            "then hydrate important entity/evidence IDs and report evidence, confidence, caveats, and next actions."
        ),
        endpoint="local://threat-investigation-guide",
        method="LOCAL",
        input_schema={
            "type": "object",
            "properties": {
                "scenario": {
                    "type": "string",
                    "enum": ["cve", "actor", "environment", "ioc", "open_ended", "prioritization"],
                    "description": "Optional scenario-specific playbook to emphasize.",
                }
            },
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="entity_resolution",
        description=(
            "Resolve raw user input, aliases, CVEs, actors, malware, campaigns, and observables into canonical entities. "
            "Use this before evidence, relationships, or assessments when the entity is not already canonical. "
            "Set expected_types aggressively (cve, actor, malware, campaign, ip, domain, url, hash, email) to reduce ambiguity. "
            "If resolution.status is ambiguous, disambiguate or retry with narrower expected_types; if not_found, stop or pivot to intel_search."
        ),
        endpoint="/v2/entity-resolution",
        method="POST",
        input_schema=_post_schema(
            {
                "query": {"type": "string", "minLength": 1, "maxLength": 1024},
                "expected_types": {"type": "array", "items": {"type": "string", "enum": list(ENTITY_TYPES)}},
                "resolution": {"type": "object"},
            }
        ),
    ),
    ToolSpec(
        name="entity_resolution_batch",
        description=(
            "Batch normalize and disambiguate 1-50 raw entity inputs. "
            "Use for bounded lists of observables, CVEs, actors, malware, campaigns, or aliases before follow-on investigation. "
            "Requires top-level agent_context; each item follows entity_resolution shape and can omit item agent_context. "
            "HTTP 200 can still include per-item errors; inspect every item.status, item.result.resolution, and item.error. "
            "Use stop_on_error=false for mixed-quality lists."
        ),
        endpoint="/v2/entity-resolution/batch",
        method="POST",
        input_schema=_post_schema(
            {
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 50,
                    "items": {
                        "type": "object",
                        "properties": {
                            "agent_context": _AGENT_CONTEXT_SCHEMA,
                            "query": {"type": "string", "minLength": 1, "maxLength": 1024},
                            "expected_types": {
                                "type": "array",
                                "items": {"type": "string", "enum": list(ENTITY_TYPES)},
                            },
                            "resolution": {"type": "object"},
                        },
                        "required": ["query"],
                        "additionalProperties": True,
                    },
                },
                "stop_on_error": {"type": "boolean", "default": False},
            }
        ),
    ),
    ToolSpec(
        name="claim_evidence",
        description=(
            "Retrieve bounded evidence for one claim about a canonical subject or raw query. "
            "Use after entity_resolution when possible. Provide exactly one of subject or query. "
            "claim_type should be one of active_exploitation, sector_targeting, actor_association, campaign_association, "
            "malware_association, relevance_to_environment, observed_in_the_wild. "
            "For sector_targeting, include context.sector. Use evidence IDs returned here with get_evidence before final synthesis."
        ),
        endpoint="/v2/evidence",
        method="POST",
        input_schema=_post_schema(
            {
                "subject": _subject_schema(),
                "query": {"type": "string", "minLength": 1, "maxLength": 1024},
                "claim_type": {"type": "string", "enum": list(CLAIM_TYPES)},
                "context": {"type": "object"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50},
                "cursor": {"type": "string", "maxLength": 512},
            }
        ),
    ),
    ToolSpec(
        name="relationships",
        description=(
            "Retrieve bounded relationship pivots for a canonical subject or raw query. "
            "Use after evidence to discover related actors, campaigns, malware, sectors, IoCs, and CVE techniques for follow-on investigation. "
            "Provide exactly one of subject or query. Omit relationship_types for all default pivots or request actor/campaign/malware/sector/ioc/technique. "
            "Hydrate important returned canonical IDs with get_entity."
        ),
        endpoint="/v2/relationships",
        method="POST",
        input_schema=_post_schema(
            {
                "subject": _subject_schema(),
                "query": {"type": "string", "minLength": 1, "maxLength": 1024},
                "relationship_types": {"type": "array", "items": {"type": "string", "enum": list(RELATIONSHIP_TYPES)}},
                "context": {"type": "object"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50},
                "cursor": {"type": "string", "maxLength": 512},
            }
        ),
    ),
    ToolSpec(
        name="intel_search",
        description=(
            "Search recent bounded intel capsules for broad or open-ended topic questions before a canonical entity is known. "
            "Use for questions like 'what happened with this campaign/topic?' Results are retrieval capsules, not assessments. "
            "Use returned canonical_entities and claim_tags as pivots into entity_resolution, claim_evidence, relationships, and assessments."
        ),
        endpoint="/v2/intel-search",
        method="POST",
        input_schema=_post_schema(
            {
                "query": {"type": "string", "minLength": 1, "maxLength": 1024},
                "time_window_days": {"type": "integer", "minimum": 1},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50},
                "source_filters": {"type": "array", "items": {"type": "string"}},
            }
        ),
    ),
    ToolSpec(
        name="prioritize",
        description=(
            "Rank environment-relevant threat signals for immediate attention. "
            "Use when the user asks what to investigate first for a specific environment. "
            "Provide environment details such as products, vendors, industry, geography, exposure, and constraints. "
            "For top-ranked signals, continue with entity_resolution, claim_evidence, relationships, and type-specific assessments."
        ),
        endpoint="/v2/prioritize",
        method="POST",
        input_schema=_post_schema(
            {
                "environment": {"type": "object"},
                "expected_categories": {"type": "array", "items": {"type": "string"}},
                "time_window_days": {"type": "integer", "minimum": 1, "maximum": 180},
                "max_items": {"type": "integer", "minimum": 1, "maximum": 100},
            }
        ),
    ),
    ToolSpec(
        name="hunt_pivots",
        description=(
            "Recommend ranked next investigative actions for subject-led or observation-led threat hunting. "
            "Use this when the user asks what to hunt next, provides weak telemetry, or has unresolved observables. "
            "Use relationships instead when you only need related entities for a resolved subject. "
            "Returned pivots include question, query_intent, why, confidence, required_fields, caveats, and optional related_entities."
        ),
        endpoint="/v2/hunt-pivots",
        method="POST",
        input_schema=_post_schema(
            {
                "subject": _subject_schema(),
                "observed": {
                    "type": "object",
                    "properties": {
                        "iocs": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "type": {"type": "string", "enum": ["ip", "domain", "url", "hash", "email"]},
                                    "value": {"type": "string", "minLength": 1},
                                    "role": {"type": "string"},
                                    "resolution_status": {"type": "string", "enum": ["resolved", "unresolved", "ambiguous", "not_found"]},
                                },
                                "required": ["type", "value"],
                                "additionalProperties": True,
                            },
                        },
                        "anomaly_summary": {"type": "string", "maxLength": 2048},
                        "techniques": {"type": "array", "items": {"type": "string"}},
                        "products": {"type": "array", "items": {"type": "string"}},
                        "telemetry_context": {"type": "object"},
                    },
                    "additionalProperties": True,
                },
                "environment_context": _environment_context_schema(),
                "options": {
                    "type": "object",
                    "properties": {
                        "max_pivots": {"type": "integer", "minimum": 1, "maximum": 20, "default": 10},
                        "include_attack_chains": {"type": "boolean", "default": True},
                    },
                    "additionalProperties": False,
                },
            }
        ),
    ),
    ToolSpec(
        name="threat_assessment",
        description=(
            "Run deterministic generic threat assessment when the input type is unknown, mixed, or agent-selected dynamically. "
            "Use type-specific tools instead when the subject is clearly a CVE, actor, or IOC. "
            "Provide exactly one of subject or query. Read resolution to confirm what was scored; treat confidence as score certainty and preserve caveats/degraded metadata."
        ),
        endpoint="/v2/threat-assessments",
        method="POST",
        input_schema=_post_schema({"subject": _subject_schema(), "query": {"type": "string", "minLength": 1, "maxLength": 1024}}),
    ),
    ToolSpec(
        name="cve_assessment",
        description=(
            "Run deterministic CVE-focused assessment for a known vulnerability. "
            "Usually resolve with expected_types=['cve'], gather active_exploitation and sector_targeting evidence, then call this with the canonical subject. "
            "Check evidence_refs, signals, caveats, degraded metadata, priority, and confidence before final recommendations."
        ),
        endpoint="/v2/cve-assessments",
        method="POST",
        input_schema=_post_schema({"subject": _subject_schema(), "query": {"type": "string", "minLength": 1, "maxLength": 1024}}),
    ),
    ToolSpec(
        name="actor_assessment",
        description=(
            "Run deterministic actor-focused assessment for a known threat actor. "
            "Resolve aliases first, gather relevance_to_environment and observed_in_the_wild evidence, inspect campaign/malware relationships, then assess. "
            "Use threat_assessment instead if the input may be a campaign or malware rather than an actor."
        ),
        endpoint="/v2/actor-assessments",
        method="POST",
        input_schema=_post_schema({"subject": _subject_schema(), "query": {"type": "string", "minLength": 1, "maxLength": 1024}}),
    ),
    ToolSpec(
        name="environment_assessment",
        description=(
            "Run deterministic environment-context assessment for a threat, CVE, actor, campaign, malware, or IOC. "
            "Use when the user asks whether a subject is relevant to their environment, assets, sector, geography, exposure, or controls. "
            "Provide exactly one of subject or query plus environment_context; include an optional environment label for readability. "
            "For CVE subjects, Kyberis hydrates CVE/KEV metadata from its own data; caller context is supplemental only. "
            "environment_context must include at least one signal such as sector, regions, internet_exposure, critical_asset_exposure, "
            "control_maturity, externally_exposed_service_count, crown_jewel_asset_count, eol_asset_count, detection_coverage, "
            "mfa_enforced, or patch_latency_days. Preserve environment_threat, priority, confidence, caveats, evidence_refs, and next actions."
        ),
        endpoint="/v2/environment-assessments",
        method="POST",
        input_schema=_post_schema(
            {
                "subject": _subject_schema(),
                "query": {"type": "string", "minLength": 1, "maxLength": 1024},
                "expected_types": {"type": "array", "items": {"type": "string", "enum": list(ENTITY_TYPES)}},
                "resolution": {"type": "object"},
                "context": {"type": "object"},
                "time_range": {"type": "object"},
                "options": {"type": "object"},
                "environment": {"type": "string"},
                "environment_context": _environment_context_schema(),
            }
        )
        | {"required": ["agent_context", "environment_context"]},
    ),
    ToolSpec(
        name="ioc_assessment",
        description=(
            "Run deterministic IOC-focused assessment for IPs, domains, URLs, hashes, or emails. "
            "Resolve the observable first, gather active_exploitation plus actor/campaign association evidence, inspect relationship pivots, then assess. "
            "Preserve lookup status, degraded metadata, caveats, evidence_refs, and next actions."
        ),
        endpoint="/v2/ioc-assessments",
        method="POST",
        input_schema=_post_schema({"subject": _subject_schema(), "query": {"type": "string", "minLength": 1, "maxLength": 1024}}),
    ),
    ToolSpec(
        name="assessments_batch",
        description=(
            "Batch run 1-50 deterministic assessments. "
            "Use for bounded IOC/CVE/actor/environment shortlists, especially IOC lists from alerts, SIEM exports, emails, or reports. "
            "Each item must include assessment_type and payload; use assessment_type='ioc_assessment' with payload.query for raw IOC strings. "
            "Supported assessment_type values are threat_assessment, cve_assessment, actor_assessment, environment_assessment, and ioc_assessment. "
            "Requires top-level agent_context; apiv2 propagates it into item payloads when omitted. "
            "HTTP 200 can still include per-item errors; inspect every item.status, item.result, item.error.status_code, caveats, and degraded metadata. "
            "Use stop_on_error=false for mixed-quality IOC lists and retry failed 429/503/504 items individually or in smaller batches."
        ),
        endpoint="/v2/assessments/batch",
        method="POST",
        input_schema=_post_schema(
            {
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 50,
                    "items": {
                        "type": "object",
                        "properties": {
                            "assessment_type": {"type": "string", "enum": list(ASSESSMENT_TYPES)},
                            "payload": _assessment_payload_schema(),
                        },
                        "required": ["assessment_type", "payload"],
                        "additionalProperties": False,
                    },
                },
                "stop_on_error": {"type": "boolean", "default": False},
            }
        ),
    ),
    ToolSpec(
        name="get_entity",
        description=(
            "Hydrate canonical entity details by canonical_id after entity_resolution, relationships, or assessment outputs. "
            "Use this before final synthesis for important pivots. Requires agent_context, which MCP maps to X-Agent-* headers."
        ),
        endpoint="/v2/entities/{canonical_id}",
        method="GET",
        requires_agent_context_headers=True,
        input_schema={
            "type": "object",
            "properties": {
                "canonical_id": {"type": "string", "minLength": 1},
                "include_aliases": {"type": "boolean", "default": True},
                "include_metadata": {"type": "boolean", "default": True},
                "agent_context": _AGENT_CONTEXT_SCHEMA,
            },
            "required": ["canonical_id", "agent_context"],
            "additionalProperties": True,
        },
    ),
    ToolSpec(
        name="get_evidence",
        description=(
            "Hydrate an evidence reference returned by claim_evidence or assessments. "
            "Use this for selected evidence_refs before final synthesis so conclusions cite specific supporting material. "
            "Requires agent_context, which MCP maps to X-Agent-* headers."
        ),
        endpoint="/v2/evidence/{evidence_id}",
        method="GET",
        requires_agent_context_headers=True,
        input_schema={
            "type": "object",
            "properties": {
                "evidence_id": {"type": "string", "minLength": 1},
                "agent_context": _AGENT_CONTEXT_SCHEMA,
            },
            "required": ["evidence_id", "agent_context"],
            "additionalProperties": True,
        },
    ),
)


def tool_by_name(name: str) -> ToolSpec | None:
    for spec in TOOL_SPECS:
        if spec.name == name:
            return spec
    return None
