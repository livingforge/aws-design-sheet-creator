"""Operators added for namespace reviews: presence, exclusivity, scope and comparison."""
import pytest

from aws_design_sheet.models import Candidate, FieldValue, Resource, Scope, ValueState
from aws_design_sheet.rule_engine import evaluate_rule, evaluate_rule_all, load_ruleset


TYPE = "AWS::S3::Bucket"


def rule(assertion, when=None, scope=None):
    raw = {"id": "S3.TEST", "version": "1.0.0", "source_type": TYPE,
           "when": when or {"op": "always"}, "assert": assertion}
    if scope:
        raw["scope"] = scope
    return load_ruleset({"ruleset_version": "1.0.0", "rules": [raw]})[0]


def known(path, value):
    return FieldValue(path=path, state=ValueState.KNOWN, selected_candidate_id="c",
                      candidates=[Candidate(id="c", raw=str(value), value=value, evidence_ids=["ev"])])


def unresolved(path):
    return FieldValue(path=path, state=ValueState.UNRESOLVED)


def resource(*fields):
    return Resource(id="r", type=TYPE, name="r",
                    scope=Scope(environment="prod", account="111111111111", region="ap-northeast-1"),
                    fields=list(fields))


def verdict(item, *fields):
    return evaluate_rule(item, resource(*fields))["verdict"]


def test_present_distinguishes_missing_from_unresolved():
    item = rule({"op": "present", "path": "/properties/A"})
    assert verdict(item) == "FAIL"
    assert verdict(item, FieldValue(path="/properties/A", state=ValueState.MISSING)) == "FAIL"
    assert verdict(item, unresolved("/properties/A")) == "NEEDS_REVIEW"
    assert verdict(item, known("/properties/A", False)) == "PASS"
    nested = rule({"op": "present", "path": "/properties/A/B"})
    assert verdict(nested, known("/properties/A", {})) == "FAIL"
    assert verdict(nested, known("/properties/A", {"B": 0})) == "PASS"
    assert verdict(nested, unresolved("/properties/A")) == "NEEDS_REVIEW"


def test_absent_and_conditions():
    when = {"op": "field_in", "path": "/properties/Mode", "values": ["X", "Y"]}
    item = rule({"op": "absent", "path": "/properties/B"}, when)
    assert verdict(item) == "NOT_APPLICABLE"
    assert verdict(item, known("/properties/Mode", "Z"), known("/properties/B", 1)) == "NOT_APPLICABLE"
    assert verdict(item, known("/properties/Mode", "X"), known("/properties/B", 1)) == "FAIL"
    assert verdict(item, known("/properties/Mode", "Y")) == "PASS"
    result = evaluate_rule(item, resource(unresolved("/properties/Mode")))
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == ["/properties/Mode"]


def test_three_valued_combinators():
    when = {"op": "all_of", "conditions": [
        {"op": "field_present", "path": "/properties/A"},
        {"op": "not", "condition": {"op": "field_present", "path": "/properties/B"}}]}
    item = rule({"op": "present", "path": "/properties/C"}, when)
    assert verdict(item) == "NOT_APPLICABLE"
    assert verdict(item, known("/properties/A", 1)) == "FAIL"
    assert verdict(item, known("/properties/A", 1), known("/properties/B", 1)) == "NOT_APPLICABLE"
    assert verdict(item, known("/properties/A", 1), unresolved("/properties/B")) == "NEEDS_REVIEW"
    # A decisive false wins over an unresolved member.
    assert verdict(item, unresolved("/properties/A"), known("/properties/B", 1)) == "NOT_APPLICABLE"
    either = rule({"op": "present", "path": "/properties/C"}, {"op": "any_of", "conditions": [
        {"op": "field_present", "path": "/properties/A"},
        {"op": "field_present", "path": "/properties/B"}]})
    assert verdict(either, unresolved("/properties/A"), known("/properties/B", 1)) == "FAIL"


@pytest.mark.parametrize("fields,expected", [
    ((), "FAIL"),
    ((("A", 1),), "PASS"),
    ((("A", 1), ("B", 2)), "FAIL"),
    ((("A", 1), ("B", None)), "FAIL"),
])
def test_count_present_exactly_one(fields, expected):
    item = rule({"op": "count_present", "paths": ["/properties/A", "/properties/B"], "min": 1, "max": 1})
    assert verdict(item, *(known(f"/properties/{name}", value) for name, value in fields)) == expected


def test_count_present_with_unresolved_member():
    item = rule({"op": "count_present", "paths": ["/properties/A", "/properties/B"], "max": 1})
    assert verdict(item, unresolved("/properties/A")) == "PASS"
    assert verdict(item, unresolved("/properties/A"), known("/properties/B", 1)) == "NEEDS_REVIEW"
    exactly = rule({"op": "count_present", "paths": ["/properties/A", "/properties/B"], "min": 1, "max": 1})
    assert verdict(exactly, unresolved("/properties/A")) == "NEEDS_REVIEW"


def test_value_in_matches_and_compare():
    allowed = rule({"op": "value_in", "path": "/properties/A", "values": ["x", "y"]})
    assert verdict(allowed) == "NOT_APPLICABLE"
    assert verdict(allowed, known("/properties/A", "x")) == "PASS"
    assert verdict(allowed, known("/properties/A", "z")) == "FAIL"
    suffix = rule({"op": "matches", "path": "/properties/Name", "pattern": r"\.fifo$"})
    assert verdict(suffix, known("/properties/Name", "a.fifo")) == "PASS"
    assert verdict(suffix, known("/properties/Name", "a")) == "FAIL"
    assert verdict(suffix, known("/properties/Name", 3)) == "FAIL"
    ordered = rule({"op": "compare", "left": {"path": "/properties/Min"}, "cmp": "le",
                    "right": {"path": "/properties/Max"}})
    assert verdict(ordered, known("/properties/Min", "1"), known("/properties/Max", "10")) == "PASS"
    assert verdict(ordered, known("/properties/Min", 5), known("/properties/Max", 2)) == "FAIL"
    assert verdict(ordered, known("/properties/Min", 5)) == "NOT_APPLICABLE"
    assert verdict(ordered, known("/properties/Min", 5), unresolved("/properties/Max")) == "NEEDS_REVIEW"
    assert verdict(ordered, known("/properties/Min", "a"), known("/properties/Max", 2)) == "NEEDS_REVIEW"


def test_scoped_rule_reports_each_array_item():
    item = rule({"op": "present", "path": "/Certificates"},
                {"op": "field_equals", "path": "/Protocol", "equals": "HTTPS"},
                scope="/properties/Listeners/*")
    listeners = known("/properties/Listeners", [
        {"Protocol": "HTTPS", "Certificates": ["c"]}, {"Protocol": "HTTPS"}, {"Protocol": "HTTP"}])
    results = evaluate_rule_all(item, resource(listeners))
    assert [(r["path"], r["verdict"]) for r in results] == [
        ("/properties/Listeners/0/Certificates", "PASS"),
        ("/properties/Listeners/1/Certificates", "FAIL"),
        ("/properties/Listeners/2/Certificates", "NOT_APPLICABLE")]
    assert results[1]["evidence_ids"] == ["ev"]
    assert [r["verdict"] for r in evaluate_rule_all(item, resource())] == ["NOT_APPLICABLE"]
    pending = evaluate_rule_all(item, resource(unresolved("/properties/Listeners")))
    assert [(r["verdict"], r["dependencies"]) for r in pending] == [
        ("NEEDS_REVIEW", ["/properties/Listeners"])]
    with pytest.raises(ValueError, match="evaluate_rule_all"):
        evaluate_rule(item, resource(listeners))


@pytest.mark.parametrize("raw", [
    {"op": "count_present", "paths": ["/properties/A"], "max": 1},
    {"op": "count_present", "paths": ["/properties/A", "/properties/A"], "max": 1},
    {"op": "count_present", "paths": ["/properties/A", "/properties/B"]},
    {"op": "value_in", "path": "/properties/A", "values": []},
    {"op": "matches", "path": "/properties/A", "pattern": "("},
    {"op": "compare", "left": {"value": 1}, "cmp": "lt", "right": {"path": "/properties/A"}},
    {"op": "compare", "left": {"path": "/properties/A"}, "cmp": "~", "right": {"value": 1}},
    {"op": "present", "path": "/properties/A/*"},
])
def test_invalid_new_assertions_rejected(raw):
    with pytest.raises(Exception):
        rule(raw)


def test_scoped_paths_must_be_relative_and_conditions_valid():
    with pytest.raises(ValueError):
        rule({"op": "present", "path": "properties/A"}, scope="/properties/L/*")
    with pytest.raises(ValueError):
        rule({"op": "present", "path": "/properties/A"},
             {"op": "all_of", "conditions": [{"op": "always"}, {"op": "always"}]})
    with pytest.raises(ValueError):
        rule({"op": "present", "path": "/properties/A"}, {"op": "not", "condition": {"op": "always"}})


def test_unique_items_and_membership():
    by_key = rule({"op": "unique", "path": "/properties/Rules", "key": "/Name"})
    assert verdict(by_key) == "NOT_APPLICABLE"
    assert verdict(by_key, known("/properties/Rules", [{"Name": "a"}, {"Name": "b"}, {}])) == "PASS"
    assert verdict(by_key, known("/properties/Rules", [{"Name": "a"}, {"Name": "a"}])) == "FAIL"
    assert verdict(by_key, unresolved("/properties/Rules")) == "NEEDS_REVIEW"
    plain = rule({"op": "unique", "path": "/properties/Ports"})
    assert verdict(plain, known("/properties/Ports", [80, 443])) == "PASS"
    assert verdict(plain, known("/properties/Ports", [80, 80])) == "FAIL"
    members = rule({"op": "items_in", "path": "/properties/Methods", "values": ["GET", "PUT"]})
    assert verdict(members, known("/properties/Methods", ["GET"])) == "PASS"
    assert verdict(members, known("/properties/Methods", ["GET", "TRACE"])) == "FAIL"
    assert verdict(members, known("/properties/Methods", "GET")) == "FAIL"


def test_contains_condition_and_root_paths_in_scoped_rules():
    item = rule({"op": "present", "path": "/Certificate"},
                {"op": "all_of", "conditions": [
                    {"op": "field_contains", "path": "$/properties/Features", "value": "TLS"},
                    {"op": "field_equals", "path": "/Protocol", "equals": "TCP"}]},
                scope="/properties/Listeners/*")
    listeners = known("/properties/Listeners", [{"Protocol": "TCP"}, {"Protocol": "UDP"}])
    results = evaluate_rule_all(item, resource(listeners, known("/properties/Features", ["TLS"])))
    assert [r["verdict"] for r in results] == ["FAIL", "NOT_APPLICABLE"]
    results = evaluate_rule_all(item, resource(listeners, known("/properties/Features", ["X"])))
    assert [r["verdict"] for r in results] == ["NOT_APPLICABLE", "NOT_APPLICABLE"]
    pending = evaluate_rule_all(item, resource(listeners, unresolved("/properties/Features")))
    assert pending[0]["verdict"] == "NEEDS_REVIEW"
    assert pending[0]["dependencies"] == ["/properties/Features"]
    with pytest.raises(ValueError):
        rule({"op": "present", "path": "$/Certificate"}, scope="/properties/Listeners/*")
