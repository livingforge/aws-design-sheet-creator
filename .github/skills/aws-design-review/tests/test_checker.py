import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Design

ROOT = Path(__file__).resolve().parents[1]


def sample():
    return json.loads((ROOT / "examples/valid.json").read_text(encoding="utf-8"))


def run(data):
    design = Design.model_validate(data)
    return Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(design)


def verdicts(result, rule):
    return [r for r in result["results"] if r["rule_id"] == rule]


def test_valid_with_false_values_and_relation():
    result = run(sample())
    assert not [r for r in result["results"] if r["verdict"] == "FAIL"]
    assert verdicts(result, "CIDR_CONTAINMENT")[0]["verdict"] == "PASS"
    assert all(r["verdict"] == "PASS" for r in verdicts(result, "PROFILE_REQUIRED"))
    assert not verdicts(result, "SCHEMA_REQUIRED")


def test_type_and_nested_schema_constraints():
    data = sample()
    fields = data["resources"][1]["fields"]
    fields[1]["candidates"][0]["value"] = "false"
    fields.append({"path": "/properties/Tags", "state": "KNOWN", "selected_candidate_id": "tags",
                   "candidates": [{"id": "tags", "raw": "tags", "value": [{"Key": "x"}], "evidence_ids": ["e-subnet"]}]})
    result = run(data)
    errors = verdicts(result, "SCHEMA_CONSTRAINT")
    assert any(r["path"] == "/properties/MapPublicIpOnLaunch" for r in errors)
    assert any(r["path"] == "/properties/Tags/0" for r in errors)


def test_cidr_outside_and_overlap():
    data = sample()
    subnet = copy.deepcopy(data["resources"][1])
    subnet["id"] = "subnet-b"
    subnet["name"] = "app-b"
    subnet["fields"][0]["candidates"][0]["value"] = "10.0.1.128/25"
    data["resources"].append(subnet)
    data["relations"].append({"id": "rel-2", "source_resource_id": "subnet-b",
                              "source_path": "/properties/VpcId", "target_resource_id": "vpc-main"})
    result = run(data)
    assert verdicts(result, "CIDR_OVERLAP")[0]["verdict"] == "FAIL"
    data["resources"][2]["fields"][0]["candidates"][0]["value"] = "10.1.0.0/24"
    result = run(data)
    assert any(r["verdict"] == "FAIL" for r in verdicts(result, "CIDR_CONTAINMENT"))


def test_overlap_survives_unknown_vpc_cidr():
    data = sample()
    subnet = copy.deepcopy(data["resources"][1])
    subnet["id"] = "subnet-b"
    subnet["name"] = "app-b"
    subnet["fields"][0]["candidates"][0]["value"] = "10.0.1.128/25"
    data["resources"].append(subnet)
    data["relations"].append({"id": "rel-2", "source_resource_id": "subnet-b",
                              "source_path": "/properties/VpcId", "target_resource_id": "vpc-main"})
    data["resources"][0]["fields"][0] = {"path": "/properties/CidrBlock", "state": "MISSING"}
    result = run(data)
    assert verdicts(result, "CIDR_OVERLAP")[0]["verdict"] == "FAIL"
    assert all(r["verdict"] == "NEEDS_REVIEW" for r in verdicts(result, "CIDR_CONTAINMENT"))


def test_unknown_reference_and_conflict():
    data = sample()
    data["relations"][0]["target_resource_id"] = "missing-vpc"
    data["resources"][1]["fields"][0] = {
        "path": "/properties/CidrBlock", "state": "CONFLICT", "candidates": [
            {"id": "one", "raw": "10.0.1.0/24", "value": "10.0.1.0/24", "evidence_ids": ["e-subnet"]},
            {"id": "two", "raw": "10.0.2.0/24", "value": "10.0.2.0/24", "evidence_ids": ["e-subnet"]}]}
    result = run(data)
    assert verdicts(result, "REFERENCE")[0]["verdict"] == "NEEDS_REVIEW"
    assert verdicts(result, "VALUE_CONFLICT")[0]["verdict"] == "NEEDS_REVIEW"
    assert not [r for r in verdicts(result, "CIDR_CONTAINMENT") if r["verdict"] == "PASS"]


def test_invalid_internal_state():
    data = sample()
    data["resources"][0]["fields"][0]["selected_candidate_id"] = None
    with pytest.raises(ValidationError):
        Design.model_validate(data)


def test_evidence_must_match_source():
    data = sample()
    data["evidence"][0]["excerpt"] = "invented"
    with pytest.raises(ValidationError, match="excerpt does not match"):
        Design.model_validate(data)


def test_missing_required_and_unknown_property():
    data = sample()
    data["relations"] = []
    data["resources"][1]["fields"].append({"path": "/properties/Unexpected", "state": "MISSING"})
    result = run(data)
    assert any(r["verdict"] == "FAIL" for r in verdicts(result, "SCHEMA_REQUIRED"))
    assert any(c["kind"] == "UNKNOWN_PROPERTY" for c in result["coverage"])


def test_null_is_a_value_and_fails_boolean_schema():
    data = sample()
    data["resources"][0]["fields"][1]["candidates"][0]["value"] = None
    result = run(data)
    assert any(r["path"] == "/properties/EnableDnsSupport" for r in verdicts(result, "SCHEMA_CONSTRAINT"))


def test_cidr_is_not_silently_normalized():
    data = sample()
    data["resources"][1]["fields"][0]["candidates"][0]["value"] = "10.0.1.7/24"
    result = run(data)
    assert verdicts(result, "CIDR_FORMAT")[0]["verdict"] == "FAIL"


def test_schema_file_integrity(tmp_path):
    import shutil
    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    (tmp_path / "schemas/CloudformationSchema.zip").write_bytes(b"corrupted")
    with pytest.raises(ValueError, match="hash mismatch"):
        Checker(tmp_path / "schemas", ROOT / "profiles/vpc-subnet.json")


def test_schema_region_is_pinned():
    data = sample()
    data["region"] = "us-east-1"
    with pytest.raises(ValueError, match="schema region"):
        run(data)


def test_external_reference_remains_unreviewed():
    data = sample()
    data["relations"] = []
    data["resources"][1]["fields"].append({"path": "/properties/VpcId", "state": "KNOWN",
        "selected_candidate_id": "external", "candidates": [{"id": "external", "raw": "vpc-123",
        "value": "vpc-123", "evidence_ids": ["e-ref"]}]})
    result = run(data)
    assert any(r["rule_id"] == "REFERENCE" and r["verdict"] == "NEEDS_REVIEW"
               for r in result["results"])
    assert any(r["rule_id"] == "CIDR_CONTAINMENT" and r["verdict"] == "NEEDS_REVIEW"
               for r in result["results"])
