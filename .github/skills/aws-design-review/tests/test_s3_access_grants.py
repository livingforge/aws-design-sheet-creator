from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Design


ROOT = Path(__file__).resolve().parents[1]


def _design(accounts):
    resources = [
        {"id": f"instance-{index}", "type": "AWS::S3::AccessGrantsInstance",
         "name": f"instance-{index}", "scope": {"environment": "prod", "account": account,
                                                  "region": "ap-northeast-1"}, "fields": []}
        for index, account in enumerate(accounts)
    ]
    return Design.model_validate({"project": "s3-access-grants", "environment": "prod",
                                  "account": "111111111111", "region": "ap-northeast-1",
                                  "resources": resources})


def _verdicts(accounts):
    result = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(_design(accounts))
    return [item["verdict"] for item in result["results"]
            if item["rule_id"] == "S3_ACCESS_GRANTS_INSTANCE_REGION_UNIQUE"]


def test_two_access_grants_instances_in_one_account_region_fail():
    assert _verdicts(["111111111111", "111111111111"]) == ["FAIL", "FAIL"]


def test_single_or_separate_account_instances_need_external_review():
    assert _verdicts(["111111111111"]) == ["NEEDS_REVIEW"]
    assert _verdicts(["111111111111", "222222222222"]) == ["NEEDS_REVIEW", "NEEDS_REVIEW"]
