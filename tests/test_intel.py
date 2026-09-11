"""Reading /v2/intel-search responses.

The bug these guard against was not a crash: the app read the capsule list
from `results`, the API sends it under `items`, and the tab answered every
query with "No intel capsules matched." So the first test is the blunt one --
the real envelope must produce capsules -- and the rest pin the capsule fields
the tab renders.
"""

from __future__ import annotations

from conftest import (
    capsule_with_entities,
    intel_entity,
    intel_search_body,
    off_topic_capsule,
    public_capsule,
    restricted_capsule,
)
from kyberis_databricks import entity_type_label, read_intel_search


def test_capsules_come_from_items_not_results():
    """The whole bug, in one assertion."""
    results = read_intel_search(intel_search_body())

    assert len(results.capsules) == 2
    assert bool(results) is True


def test_a_results_shaped_body_yields_nothing():
    """The shape the app used to expect is not a shape the API sends.

    If this ever starts passing with capsules, the API grew a second envelope
    key and the reader should be told about it deliberately.
    """
    body = intel_search_body()
    body["results"] = body.pop("items")

    results = read_intel_search(body)

    assert results.capsules == []
    assert bool(results) is False


def test_capsule_carries_the_fields_the_tab_renders():
    capsule = read_intel_search(intel_search_body([public_capsule()])).capsules[0]

    assert capsule.title.startswith("Medusa ransomware tallies hundreds of new victims")
    assert capsule.published_date == "2026-08-18"
    assert capsule.source == "feed"
    assert capsule.match_score == 0.08
    assert capsule.match_reasons == ["token_hits:1", "fresh_30d"]
    assert capsule.claim_tags[0] == "beyondtrust"
    assert "Department of Health and Human Services (HHS)" in capsule.claim_tags
    assert capsule.abstract_stub.startswith("A US government advisory (CISA, FBI, HHS)")
    assert capsule.report_id == 111737


def test_pivots_are_grouped_by_entity_type_in_api_order():
    """canonical_entities are the documented pivot path, so they get grouped."""
    capsule = read_intel_search(intel_search_body([capsule_with_entities()])).capsules[0]

    grouped = capsule.entities_by_type()

    assert list(grouped) == ["actor", "malware", "cve"]
    assert [entity.canonical_id for entity in grouped["actor"]] == ["actor--medusa"]
    assert grouped["cve"][0].canonical_name == "CVE-2024-57727"
    assert grouped["actor"][0].label == "Medusa (0.85)"


def test_captured_capsules_carry_tags_but_no_pivots():
    """The captured bodies exercise the no-pivot path, tags present.

    canonical_entities and claim_tags are independent: a capsule can carry one
    and not the other, and the rendering must not treat either as implying
    the other.
    """
    results = read_intel_search(intel_search_body())

    assert results.entity_count == 0
    assert all(capsule.entities == [] for capsule in results.capsules)
    assert all(capsule.claim_tags for capsule in results.capsules)


def test_public_capsule_links_out_and_restricted_one_does_not():
    """access_level, not the presence of a url, is the API's own word on this."""
    public, restricted = read_intel_search(
        intel_search_body([public_capsule(), restricted_capsule()])
    ).capsules

    assert public.is_public is True
    assert public.url.startswith("https://")
    assert restricted.is_public is False
    assert restricted.url is None
    assert restricted.access_hint == "Restricted source; use entitled retrieval path."


def test_empty_result_set_is_a_status_not_an_error():
    """"We looked and found nothing" is a result, the same as in resolution."""
    results = read_intel_search(intel_search_body([]))

    assert results.status == "no_results"
    assert results.capsules == []
    assert bool(results) is False


def test_truncation_and_warnings_come_off_metadata():
    results = read_intel_search(
        intel_search_body(truncated=True, warnings=["empty_query"])
    )

    assert results.truncated is True
    assert results.warnings == ["empty_query"]


def test_capsule_without_entities_groups_to_nothing():
    capsule = read_intel_search(intel_search_body([off_topic_capsule()])).capsules[0]

    assert capsule.entities == []
    assert capsule.entities_by_type() == {}


def test_entity_without_a_name_or_id_is_not_a_pivot():
    """A blank chip is worse than no chip: it cannot be pivoted on."""
    item = capsule_with_entities()
    item["canonical_entities"] = [
        intel_entity(canonical_id="", canonical_name=""),
        intel_entity("malware", "malware--lockbit", "LockBit", 0.9),
    ]

    capsule = read_intel_search(intel_search_body([item])).capsules[0]

    assert [entity.canonical_name for entity in capsule.entities] == ["LockBit"]


def test_missing_optional_fields_do_not_break_a_capsule():
    """Every capsule field except title is nullable or absent somewhere real."""
    item = {"title": "Bare capsule", "access_level": "restricted"}

    capsule = read_intel_search(intel_search_body([item])).capsules[0]

    assert capsule.title == "Bare capsule"
    assert capsule.published_date is None
    assert capsule.match_score is None
    assert capsule.claim_tags == []
    assert capsule.entities == []
    assert capsule.is_public is False


def test_a_non_dict_body_is_read_as_no_results():
    """The client hands back a str body when the API returns non-JSON."""
    results = read_intel_search("upstream timeout")

    assert results.status == "no_results"
    assert results.capsules == []


def test_entity_label_omits_a_missing_confidence():
    item = capsule_with_entities()
    entity = intel_entity("campaign", "campaign--midnight", "Midnight Blizzard Ops")
    entity.pop("confidence")
    item["canonical_entities"] = [entity]

    capsule = read_intel_search(intel_search_body([item])).capsules[0]

    assert capsule.entities[0].label == "Midnight Blizzard Ops"


def test_entity_type_headings_are_not_naive_plurals():
    """".title() + s" gets three of the four types wrong."""
    assert entity_type_label("actor") == "Actors"
    assert entity_type_label("malware") == "Malware"
    assert entity_type_label("campaign") == "Campaigns"
    assert entity_type_label("cve") == "CVEs"


def test_an_unknown_entity_type_still_gets_a_heading():
    """The API's Literal could grow a fifth type before this repo hears about it."""
    assert entity_type_label("sector") == "Sector"
    assert entity_type_label("") == "Entities"


def test_a_stub_cut_mid_sentence_is_marked_as_cut():
    """Captured stubs end mid-clause well under the API's 320-char cap."""
    capsule = read_intel_search(intel_search_body([public_capsule()])).capsules[0]

    assert capsule.abstract_stub.endswith("bringing")
    assert capsule.abstract.endswith("bringing…")


def test_a_complete_stub_is_left_alone():
    item = public_capsule()
    item["abstract_stub"] = "A complete sentence."

    capsule = read_intel_search(intel_search_body([item])).capsules[0]

    assert capsule.abstract == "A complete sentence."


def test_a_missing_stub_stays_missing():
    item = public_capsule()
    item["abstract_stub"] = ""

    capsule = read_intel_search(intel_search_body([item])).capsules[0]

    assert capsule.abstract is None
