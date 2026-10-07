import hashlib
import json
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Candidate, Design, FieldValue, Resource, ValueState


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
PROFILE = ROOT / "profiles/vpc-subnet.json"


def sample_design():
    return Design.model_validate_json((ROOT / "examples/valid.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("service,config", [
    ("RDS", "ServerlessV2ScalingConfiguration"),
    ("Neptune", "ServerlessScalingConfiguration"),
])
@pytest.mark.parametrize("value,expected", [(8.5, "PASS"), (8.25, "FAIL"),
                                          ({"$state": "UNRESOLVED"}, "NEEDS_REVIEW")])
def test_serverless_half_step_rules_run_through_checker(service, config, value, expected):
    data = sample_design()
    data.resources.append(Resource(
        id="cluster", type=f"AWS::{service}::DBCluster", name="cluster",
        scope=data.resources[0].scope, fields=[FieldValue(
            path=f"/properties/{config}", state=ValueState.KNOWN, selected_candidate_id="capacity",
            candidates=[Candidate(id="capacity", raw=str(value),
                                  value={"MinCapacity": value, "MaxCapacity": value},
                                  evidence_ids=["e-vpc"])])]))
    result = Checker(SCHEMAS, PROFILE).check(data)
    rows = [row for row in result["results"] if row["resource_id"] == "cluster"
            and row["rule_id"].endswith("_HALF_STEPS")]
    assert len(rows) == 2
    assert all(row["verdict"] == expected and row["source_urls"]
               and row["evidence_ids"] == ["e-vpc"] for row in rows)
    if expected == "NEEDS_REVIEW":
        assert all(row["dependencies"] for row in rows)


def test_default_ruleset_version_and_unresearched_coverage():
    result = Checker(SCHEMAS, PROFILE).check(sample_design())
    raw = (ROOT / "rules/ruleset.json").read_bytes()
    assert result["versions"]["ruleset"] == json.loads(raw)["ruleset_version"]
    assert result["versions"]["ruleset_sha256"] == hashlib.sha256(raw).hexdigest()
    assert any(item["kind"] == "RULE_REVIEW_REQUIRED" for item in result["coverage"])


def test_registered_rule_runs_and_is_traced(tmp_path):
    ledger = json.loads((ROOT / "rules/ledger.json").read_text(encoding="utf-8"))
    existing_ids = ledger["types"]["AWS::EC2::VPC"]["rule_ids"]
    ledger["types"]["AWS::EC2::VPC"].update(
        state="RULES_REGISTERED", reviewed_at="2026-09-29",
        source_urls=["https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpc.html"],
        rule_ids=[*existing_ids, "TEST.VPC.OPTIONAL_FIELD"], open_questions=[])
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    baseline = json.loads((ROOT / "rules/ruleset.json").read_text(encoding="utf-8"))["rules"]
    ruleset = {"ruleset_version": "test", "rules": [*baseline, {
        "id": "TEST.VPC.OPTIONAL_FIELD", "version": "1", "source_type": "AWS::EC2::VPC",
        "when": {"op": "always"},
        "assert": {"op": "required", "path": "/properties/OptionalTestField"}}]}
    ruleset_path = tmp_path / "ruleset.json"
    ruleset_path.write_text(json.dumps(ruleset), encoding="utf-8")
    result = Checker(SCHEMAS, PROFILE, ledger_path, ruleset_path).check(sample_design())
    findings = [item for item in result["results"] if item["rule_id"] == "TEST.VPC.OPTIONAL_FIELD"]
    assert len(findings) == 1
    assert findings[0]["verdict"] == "NEEDS_REVIEW"
    assert findings[0]["dependencies"] == ["/properties/OptionalTestField"]
    assert result["versions"]["ruleset"] == "test"
    assert not any(item["kind"] == "RULE_UNRESEARCHED" and item["resource_id"] == "vpc-main"
                   for item in result["coverage"])


def test_unclaimed_ruleset_rule_is_rejected(tmp_path):
    path = tmp_path / "ruleset.json"
    baseline = json.loads((ROOT / "rules/ruleset.json").read_text(encoding="utf-8"))["rules"]
    path.write_text(json.dumps({"ruleset_version": "test", "rules": [*baseline, {
        "id": "TEST.UNCLAIMED", "version": "1", "source_type": "AWS::S3::Bucket",
        "when": {"op": "always"}, "assert": {"op": "required", "path": "/properties/BucketName"}}]}),
        encoding="utf-8")
    with pytest.raises(ValueError, match="absent from review ledger"):
        Checker(SCHEMAS, PROFILE, ROOT / "rules/ledger.json", path)


def test_checker_cache_revalidates_changed_files_at_same_paths(tmp_path):
    ruleset_path = tmp_path / "ruleset.json"
    ledger_path = tmp_path / "ledger.json"
    ruleset = json.loads((ROOT / "rules/ruleset.json").read_text(encoding="utf-8"))
    ledger = json.loads((ROOT / "rules/ledger.json").read_text(encoding="utf-8"))
    ruleset_path.write_text(json.dumps(ruleset), encoding="utf-8")
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    Checker(SCHEMAS, PROFILE, ledger_path, ruleset_path)

    ruleset["rules"].append({
        "id": "TEST.UNCLAIMED", "version": "1", "source_type": "AWS::S3::Bucket",
        "when": {"op": "always"},
        "assert": {"op": "required", "path": "/properties/BucketName"}})
    ruleset_path.write_text(json.dumps(ruleset), encoding="utf-8")
    with pytest.raises(ValueError, match="absent from review ledger"):
        Checker(SCHEMAS, PROFILE, ledger_path, ruleset_path)

    ruleset["rules"].pop()
    ruleset_path.write_text(json.dumps(ruleset), encoding="utf-8")
    ledger["types"]["AWS::S3::Bucket"]["state"] = "INVALID"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid ledger state"):
        Checker(SCHEMAS, PROFILE, ledger_path, ruleset_path)
