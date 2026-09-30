import json
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Design


ROOT = Path(__file__).resolve().parents[1]


def findings(count, *, second_account=None):
    data = json.loads((ROOT / "examples/valid.json").read_text(encoding="utf-8"))
    for index in range(count):
        scope = data["resources"][0]["scope"].copy()
        if index == 1 and second_account:
            scope["account"] = second_account
        data["resources"].append({"id": f"group-{index}", "type": "AWS::AIOps::InvestigationGroup",
                                  "name": f"group-{index}", "scope": scope, "fields": []})
    result = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(
        Design.model_validate(data))
    return [item for item in result["results"]
            if item["rule_id"] == "AIOPS_INVESTIGATION_GROUP_REGION_UNIQUE"]


def test_one_investigation_group_per_account_region():
    assert [item["verdict"] for item in findings(1)] == ["PASS"]
    assert [item["verdict"] for item in findings(2)] == ["FAIL", "FAIL"]
    assert [item["verdict"] for item in findings(2, second_account="222222222222")] == ["PASS", "PASS"]
