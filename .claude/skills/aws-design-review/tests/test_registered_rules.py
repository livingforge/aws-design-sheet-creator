"""Every registered declarative rule and reference must carry checkable evidence."""
import json
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker, REFERENCE_TYPES
from aws_design_sheet.models import Design
from aws_design_sheet.rule_engine import load_ruleset
from aws_design_sheet.rule_review import (PinnedSchemas, basis_errors, example_errors,
                                          load_reference_catalog, required_example_verdicts)


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = PinnedSchemas(ROOT / "schemas")
RULES = load_ruleset(json.loads((ROOT / "rules/ruleset.json").read_text(encoding="utf-8")))
REFERENCES_PATH = ROOT / "rules/references.json"
REFERENCES = (json.loads(REFERENCES_PATH.read_text(encoding="utf-8")) if REFERENCES_PATH.exists()
              else {"catalog_version": "0", "references": []})


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_rule_basis_quotes_are_in_the_pinned_schema(rule):
    assert rule.basis, "rule needs a basis quote"
    assert rule.source_urls and rule.source_checked_at
    assert basis_errors(rule.basis, SCHEMAS.schema(rule.source_type), rule.id) == []


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.id)
def test_rule_examples_cover_and_reproduce_verdicts(rule):
    assert required_example_verdicts(rule) <= {example["verdict"] for example in rule.examples}
    assert example_errors(rule) == []


def test_reference_catalog_is_valid_and_quoted():
    catalog = load_reference_catalog(REFERENCES, SCHEMAS.manifest["types"])
    assert not set(catalog) & set(REFERENCE_TYPES)
    for item in REFERENCES["references"]:
        assert basis_errors(item["basis"], SCHEMAS.schema(item["source_type"]), item["path"]) == []


def test_catalog_reference_checks_target_type(tmp_path):
    catalog = {"catalog_version": "test", "references": [{
        "source_type": "AWS::EC2::RouteTable", "path": "/properties/VpcId",
        "target_type": "AWS::EC2::VPC",
        "basis": [{"pointer": "/properties/VpcId", "quote": "The ID of the VPC."}]}]}
    path = tmp_path / "references.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    data = json.loads((ROOT / "examples/valid.json").read_text(encoding="utf-8"))
    scope = data["resources"][0]["scope"]
    data["resources"].append({"id": "rt", "type": "AWS::EC2::RouteTable", "name": "rt",
                              "scope": scope, "fields": []})
    data["relations"].append({"id": "rt-vpc", "source_resource_id": "rt",
                              "source_path": "/properties/VpcId",
                              "target_resource_id": data["resources"][0]["id"]})
    checker = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json", references_path=path)
    result = checker.check(Design.model_validate(data))
    rows = [row for row in result["results"] if row["resource_id"] == "rt" and row["rule_id"] == "REFERENCE"]
    assert [row["verdict"] for row in rows] == ["PASS"]
    assert result["versions"]["references"] == "test"
    catalog["references"][0]["target_type"] = "AWS::EC2::Subnet"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    result = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json",
                     references_path=path).check(Design.model_validate(data))
    rows = [row for row in result["results"] if row["resource_id"] == "rt" and row["rule_id"] == "REFERENCE"]
    assert [row["verdict"] for row in rows] == ["FAIL"]


def test_catalog_cannot_override_built_in_reference(tmp_path):
    path = tmp_path / "references.json"
    path.write_text(json.dumps({"catalog_version": "t", "references": [{
        "source_type": "AWS::EC2::Subnet", "path": "/properties/VpcId",
        "target_type": "AWS::EC2::SecurityGroup",
        "basis": [{"pointer": "/properties/VpcId", "quote": "x"}]}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="conflicts with built-in"):
        Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json", references_path=path)


def test_reference_paths_may_wildcard_any_array_level():
    from aws_design_sheet.checker import reference_type
    catalog = {("AWS::Test::Thing", "/properties/Origins/*/RoleArn"): "AWS::IAM::Role"}
    assert reference_type("AWS::Test::Thing", "/properties/Origins/2/RoleArn", catalog) == "AWS::IAM::Role"
    assert reference_type("AWS::Test::Thing", "/properties/Origins/x/RoleArn", catalog) is None
    assert reference_type("AWS::Test::Thing", "/properties/Origins/2", catalog) is None
