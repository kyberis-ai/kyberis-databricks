"""Reading ``POST /v2/intel-search`` responses.

Intel search answers broad, open-ended questions ("what happened with this
campaign?") with bounded retrieval capsules rather than assessments. The value
in a capsule is not its prose: it is the ``canonical_entities`` and
``claim_tags`` the API extracted, which are the pivots into
``entity_resolution``, ``claim_evidence``, ``relationships``, and the
assessment tools.

The envelope is::

    {"status": "ok" | "no_results",
     "query": str,
     "max_results": int,
     "items": [capsule, ...],
     "metadata": {"item_count": int, "truncated": bool, "warnings": [str]}}

Note ``items``. The capsule list has never been sent under any other key, and
reading one -- ``results`` -- meant the app rendered "no matches" for every
query ever run against it, with no error to notice. That is why this module
exists apart from the Streamlit page: the shape can be pinned by a test
against a captured response, which a module-level ``st.*`` script cannot be.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Plural display names for the four entity types intel search extracts.
# Derived from the type rather than pluralized programmatically, because the
# obvious rules get three of the four wrong ("Malwares", "Cves").
ENTITY_TYPE_LABELS = {
    "actor": "Actors",
    "malware": "Malware",
    "campaign": "Campaigns",
    "cve": "CVEs",
}


def entity_type_label(entity_type: str) -> str:
    """Plural heading for a pivot group, falling back to the raw type."""
    return ENTITY_TYPE_LABELS.get(entity_type, str(entity_type or "Entities").title())


# Capsule ordering is the API's: it sorts by match_score descending, then
# published_date, then title. Re-sorting here would discard the freshness and
# token-match weighting that ranking already applied.


@dataclass(frozen=True)
class IntelEntity:
    """One ``canonical_entities`` pivot: an entity the capsule is about."""

    entity_type: str
    canonical_id: str
    canonical_name: str
    confidence: float | None = None

    @property
    def label(self) -> str:
        """``Name`` or ``Name (0.88)`` -- what a reader scans."""
        if self.confidence is None:
            return self.canonical_name
        return f"{self.canonical_name} ({self.confidence:.2f})"


@dataclass(frozen=True)
class IntelCapsule:
    """One bounded report capsule from ``items``."""

    title: str
    report_id: int | None = None
    report_uuid: str | None = None
    published_date: str | None = None
    source: str | None = None
    access_level: str | None = None
    url: str | None = None
    access_hint: str | None = None
    abstract_stub: str | None = None
    match_score: float | None = None
    match_reasons: list[str] = field(default_factory=list)
    entities: list[IntelEntity] = field(default_factory=list)
    claim_tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def abstract(self) -> str | None:
        """``abstract_stub`` with an ellipsis when it was cut mid-sentence.

        The API caps the stub at 320 characters, but that is not the only cut:
        captured stubs run far shorter than the cap and still end mid-clause
        ("...in the past year, bringing"), because the upstream summary was
        already truncated. Ending punctuation is the reliable signal, not
        length, and marking it beats rendering a sentence that just stops.
        """
        if not self.abstract_stub:
            return None
        if self.abstract_stub[-1] in ".!?\u2026":
            return self.abstract_stub
        return f"{self.abstract_stub}\u2026"

    @property
    def is_public(self) -> bool:
        """Whether the capsule links out.

        ``access_level`` is the API's own word on this, and it is the one to
        trust: a restricted capsule carries ``url=None`` and an
        ``access_hint`` naming the entitled retrieval path instead.
        """
        return self.access_level == "public" and bool(self.url)

    def entities_by_type(self) -> dict[str, list[IntelEntity]]:
        """Pivots grouped by ``actor`` / ``malware`` / ``campaign`` / ``cve``.

        Insertion-ordered, so the grouping follows the API's own ordering
        within each type instead of imposing an alphabetical one.
        """
        grouped: dict[str, list[IntelEntity]] = {}
        for entity in self.entities:
            grouped.setdefault(entity.entity_type, []).append(entity)
        return grouped


@dataclass(frozen=True)
class IntelSearchResults:
    """A whole intel-search response, read into display-ready parts."""

    status: str
    query: str
    capsules: list[IntelCapsule] = field(default_factory=list)
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.capsules)

    @property
    def entity_count(self) -> int:
        return sum(len(capsule.entities) for capsule in self.capsules)


def read_intel_search(body: Any) -> IntelSearchResults:
    """Read an intel-search response envelope.

    Tolerant of missing optional fields -- every capsule field except
    ``title`` is nullable or absent in some real response -- but deliberately
    not tolerant of the envelope key: only ``items`` is read, because guessing
    at alternatives is what let the original mistake go unnoticed.
    """
    envelope = body if isinstance(body, dict) else {}
    metadata = envelope.get("metadata") if isinstance(envelope.get("metadata"), dict) else {}
    items = envelope.get("items")

    capsules = [
        _read_capsule(item)
        for item in (items if isinstance(items, list) else [])
        if isinstance(item, dict)
    ]

    return IntelSearchResults(
        status=_text(envelope.get("status")) or ("ok" if capsules else "no_results"),
        query=_text(envelope.get("query")) or "",
        capsules=capsules,
        truncated=bool(metadata.get("truncated")),
        warnings=_string_list(metadata.get("warnings")),
    )


def _read_capsule(item: dict) -> IntelCapsule:
    return IntelCapsule(
        # title is required by the API and defaulted to "Untitled report"
        # there, so this fallback is for a malformed body, not a normal one.
        title=_text(item.get("title")) or "Untitled report",
        report_id=_int(item.get("report_id")),
        report_uuid=_text(item.get("report_uuid")),
        published_date=_text(item.get("published_date")),
        source=_text(item.get("source")),
        access_level=_text(item.get("access_level")),
        url=_text(item.get("url")),
        access_hint=_text(item.get("access_hint")),
        abstract_stub=_text(item.get("abstract_stub")),
        match_score=_number(item.get("match_score")),
        match_reasons=_string_list(item.get("match_reasons")),
        entities=_read_entities(item.get("canonical_entities")),
        claim_tags=_string_list(item.get("claim_tags")),
        raw=item,
    )


def _read_entities(value: Any) -> list[IntelEntity]:
    entities: list[IntelEntity] = []
    for entry in value if isinstance(value, list) else []:
        if not isinstance(entry, dict):
            continue
        name = _text(entry.get("canonical_name"))
        canonical_id = _text(entry.get("canonical_id"))
        # A pivot with neither a name to show nor an id to pivot on is not a
        # pivot; drop it rather than rendering a blank chip.
        if not name and not canonical_id:
            continue
        entities.append(
            IntelEntity(
                entity_type=_text(entry.get("entity_type")) or "unknown",
                canonical_id=canonical_id or "",
                canonical_name=name or canonical_id or "",
                confidence=_number(entry.get("confidence")),
            )
        )
    return entities


def _text(value: Any) -> str | None:
    text = str(value if value is not None else "").strip()
    return text or None


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(entry).strip() for entry in value if str(entry).strip()]
