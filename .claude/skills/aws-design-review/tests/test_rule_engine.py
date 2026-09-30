"""Contract tests for the standalone declarative rule evaluator."""
import pytest

from aws_design_sheet.models import Candidate, FieldValue, Resource, Scope, ValueState
from aws_design_sheet.rule_engine import evaluate_rule, load_ruleset


TYPE = "AWS::S3::Bucket"


def rule(assertion, when=None):
    return load_ruleset({"ruleset_version": "1.0.0", "rules": [{
        "id": "S3.TEST", "version": "1.0.0", "source_type": TYPE,
        "when": when or {"op": "always"}, "assert": assertion
    }]})[0]


def resource(*fields):
    return Resource(id="res-1", type=TYPE, name="assets",
                    scope=Scope(environment="prod", account="111111111111", region="ap-northeast-1"),
                    fields=list(fields))


def field(path, state, value=None):
    if state == ValueState.KNOWN:
        return FieldValue(path=path, state=state,
                          candidates=[Candidate(id="c", raw=str(value), value=value, evidence_ids=["ev-1"])],
                          selected_candidate_id="c")
    if state == ValueState.CONFLICT:
        return FieldValue(path=path, state=state,
                          candidates=[Candidate(id="a", raw="a", value="a", evidence_ids=["ev-1"]),
                                      Candidate(id="b", raw="b", value="b", evidence_ids=["ev-2"])])
    return FieldValue(path=path, state=state)


@pytest.mark.parametrize("state", [ValueState.MISSING, ValueState.CONFLICT,
                                      ValueState.INFERRED, ValueState.UNRESOLVED,
                                      ValueState.NOT_APPLICABLE])
def test_required_unknown_states_need_review(state):
    path = "/properties/BucketName"
    if state == ValueState.INFERRED:
        item = FieldValue(path=path, state=state,
                          candidates=[Candidate(id="a", raw="draft", value="draft")])
    else:
        item = field(path, state)
    result = evaluate_rule(rule({"op": "required", "path": path}), resource(item))
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == [path]


@pytest.mark.parametrize("value", [False, 0, "", None])
def test_required_known_values_are_present(value):
    path = "/properties/TestValue"
    result = evaluate_rule(rule({"op": "required", "path": path}),
                           resource(field(path, ValueState.KNOWN, value)))
    assert result["verdict"] == "PASS"
    assert result["evidence_ids"] == ["ev-1"]


def test_field_equals_and_strict_json_types():
    path = "/properties/TestValue"
    condition = {"op": "field_equals", "path": path, "equals": 0}
    assertion = {"op": "field_equals", "path": path, "equals": False}
    result = evaluate_rule(rule(assertion), resource(field(path, ValueState.KNOWN, 0)))
    assert result["verdict"] == "FAIL"
    result = evaluate_rule(rule(assertion, when=condition), resource(field(path, ValueState.KNOWN, False)))
    assert result["verdict"] == "NOT_APPLICABLE"
    result = evaluate_rule(rule({"op": "field_equals", "path": path, "equals": 0}, when=condition),
                           resource(field(path, ValueState.KNOWN, 0)))
    assert result["verdict"] == "PASS"


def test_unknown_condition_short_circuits_assertion():
    result = evaluate_rule(rule({"op": "required", "path": "/properties/BucketName"},
                                {"op": "field_equals", "path": "/properties/Enabled", "equals": True}),
                           resource())
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == ["/properties/Enabled"]


def test_nested_json_pointer_reads_known_object_and_array():
    item = field("/properties/Configuration", ValueState.KNOWN,
                 {"items": [{"enabled": False}]})
    assertion = {"op": "field_equals", "path": "/properties/Configuration/items/0/enabled",
                 "equals": False}
    result = evaluate_rule(rule(assertion), resource(item))
    assert result["verdict"] == "PASS"
    assert result["evidence_ids"] == ["ev-1"]
    missing = evaluate_rule(rule({"op": "required", "path": "/properties/Configuration/items/1"}),
                            resource(item))
    assert missing["verdict"] == "NEEDS_REVIEW"


@pytest.mark.parametrize("size,verdict", [(1, "FAIL"), (2, "PASS"), (3, "PASS"), (4, "FAIL")])
def test_cardinality(size, verdict):
    path = "/properties/Items"
    result = evaluate_rule(rule({"op": "cardinality", "path": path, "min": 2, "max": 3}),
                           resource(field(path, ValueState.KNOWN, list(range(size)))))
    assert result["verdict"] == verdict
    assert result["actual"] == size


def test_cardinality_type_and_missing():
    path = "/properties/Items"
    condition = rule({"op": "cardinality", "path": path, "min": 1})
    assert evaluate_rule(condition, resource())["verdict"] == "NEEDS_REVIEW"
    assert evaluate_rule(condition, resource(field(path, ValueState.KNOWN, "one")))["verdict"] == "FAIL"


@pytest.mark.parametrize("assertion", [
    {"op": "unknown", "path": "/properties/A"},
    {"op": "required", "path": "/properties/"},
    {"op": "required", "path": "/properties/A~3B"},
    {"op": "required", "path": "properties/A"},
    {"op": "cardinality", "path": "/properties/A"},
    {"op": "cardinality", "path": "/properties/A", "min": True},
    {"op": "cardinality", "path": "/properties/A", "min": 3, "max": 2},
    {"op": "field_equals", "path": "/properties/A"},
    {"op": "required", "path": "/properties/A", "bogus": 1},
])
def test_invalid_assertions_are_rejected(assertion):
    with pytest.raises(ValueError):
        rule(assertion)


def test_invalid_condition_and_duplicate_ids_are_rejected():
    with pytest.raises(ValueError, match="unknown when operator"):
        rule({"op": "required", "path": "/properties/A"}, {"op": "any"})
    valid = {"id": "S3.TEST", "version": "1", "source_type": TYPE,
             "when": {"op": "always"}, "assert": {"op": "required", "path": "/properties/A"}}
    with pytest.raises(ValueError, match="duplicate rule id"):
        load_ruleset({"ruleset_version": "1", "rules": [valid, valid]})


@pytest.mark.parametrize("bad", [(1, 2), {1: "value"}, float("nan")])
def test_non_json_equals_value_rejected(bad):
    with pytest.raises(ValueError, match="JSON value"):
        rule({"op": "field_equals", "path": "/properties/A", "equals": bad})


def test_metadata_types_and_paths_are_validated():
    base = {"id": "S3.TEST", "version": "1.0.0", "source_type": TYPE,
            "when": {"op": "always"}, "assert": {"op": "required", "path": "/properties/A"},
            "authority": "AWS_SPEC", "source_urls": ["https://example.test"],
            "dependencies": ["/properties/A"]}
    assert load_ruleset({"ruleset_version": "1", "rules": [base]})[0].id == "S3.TEST"
    result = evaluate_rule(load_ruleset({"ruleset_version": "1", "rules": [base]})[0], resource())
    assert result["source_urls"] == ["https://example.test"]
    assert result["authority"] == "AWS_SPEC"
    for replacement in ({"dependencies": ["bad/path"]}, {"source_urls": [12]},
                        {"authority": "unknown"}, {"source_type": "invalid"}):
        with pytest.raises(ValueError):
            load_ruleset({"ruleset_version": "1", "rules": [{**base, **replacement}]})


def test_wrong_resource_type_rejected():
    other = Resource(id="res-1", type="AWS::EC2::VPC", name="vpc",
                     scope=Scope(environment="prod", account="1", region="ap-northeast-1"))
    with pytest.raises(ValueError, match="resource type"):
        evaluate_rule(rule({"op": "required", "path": "/properties/A"}), other)
