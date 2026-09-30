import json
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Design


ROOT = Path(__file__).resolve().parents[1]


def known(path, value):
    return {"path": path, "state": "KNOWN", "selected_candidate_id": "value",
            "candidates": [{"id": "value", "raw": str(value), "value": value,
                            "evidence_ids": ["e-vpc"]}]}


def check(type_name, fields, relation_target=None):
    data = json.loads((ROOT / "examples/valid.json").read_text(encoding="utf-8"))
    scope = data["resources"][0]["scope"]
    data["resources"].append({"id": "subject", "type": type_name,
                              "name": "subject", "scope": scope, "fields": fields})
    if relation_target is not None:
        data["resources"].append({"id": "application", "type": relation_target,
                                  "name": "application", "scope": scope, "fields": []})
        data["relations"].append({"id": "application-ref", "source_resource_id": "subject",
                                  "source_path": "/properties/ApplicationArn",
                                  "target_resource_id": "application"})
    output = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(
        Design.model_validate(data))
    return [row for row in output["results"] if row["resource_id"] == "subject"]


def test_analyzer_configuration_union():
    resource = "AWS::AccessAnalyzer::Analyzer"
    path = "/properties/AnalyzerConfiguration"
    rule = "ACCESS_ANALYZER_CONFIGURATION_UNION"
    def verdict(fields):
        return next(row["verdict"] for row in check(resource, fields) if row["rule_id"] == rule)
    assert verdict([]) == "NOT_APPLICABLE"
    assert verdict([known(path, {"UnusedAccessConfiguration": {}})]) == "PASS"
    assert verdict([known(path, {"InternalAccessConfiguration": {}})]) == "PASS"
    assert verdict([known(path, {"UnusedAccessConfiguration": {},
                                "InternalAccessConfiguration": {}})]) == "FAIL"
    assert verdict([{"path": path, "state": "UNRESOLVED"}]) == "NEEDS_REVIEW"


def test_entitlement_application_reference():
    entitlement = "AWS::AccountAccess::Entitlement"
    application = "AWS::AccountAccess::Application"
    def references(*args, **kwargs):
        return [row for row in check(*args, **kwargs) if row["rule_id"] == "REFERENCE"]
    assert references(entitlement, [], application)[0]["verdict"] == "PASS"
    assert references(entitlement, [], "AWS::EC2::VPC")[0]["verdict"] == "FAIL"
    external = known("/properties/ApplicationArn",
                     "arn:aws:account-access:ap-northeast-1:111111111111:application/example")
    assert references(entitlement, [external])[0]["verdict"] == "NEEDS_REVIEW"
