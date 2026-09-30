import json
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Design


ROOT = Path(__file__).resolve().parents[1]


def known(path, value, candidate):
    return {"path": path, "state": "KNOWN", "selected_candidate_id": candidate,
            "candidates": [{"id": candidate, "raw": str(value), "value": value,
                            "evidence_ids": ["e-vpc"]}]}


def check(type_name, fields):
    data = json.loads((ROOT / "examples/valid.json").read_text(encoding="utf-8"))
    data["resources"].append({"id": "arc", "type": type_name, "name": "arc",
                              "scope": data["resources"][0]["scope"], "fields": fields})
    result = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(
        Design.model_validate(data))
    return {item["rule_id"]: item for item in result["results"] if item["resource_id"] == "arc"
            and item["rule_id"].startswith("ARC_")}


def test_region_switch_regions_and_primary():
    plan = "AWS::ARCRegionSwitch::Plan"
    regions = known("/properties/Regions", ["ap-northeast-1", "us-west-2"], "regions")
    primary = known("/properties/PrimaryRegion", "ap-northeast-1", "primary")
    good = check(plan, [regions, primary])
    assert good["ARC_PLAN_DISTINCT_REGIONS"]["verdict"] == "PASS"
    assert good["ARC_PLAN_PRIMARY_REGION_INCLUDED"]["verdict"] == "PASS"
    duplicate = check(plan, [known("/properties/Regions", ["ap-northeast-1"] * 2, "same")])
    assert duplicate["ARC_PLAN_DISTINCT_REGIONS"]["verdict"] == "FAIL"
    assert duplicate["ARC_PLAN_PRIMARY_REGION_INCLUDED"]["verdict"] == "NOT_APPLICABLE"
    wrong_primary = check(plan, [regions, known("/properties/PrimaryRegion", "eu-west-1", "wrong")])
    assert wrong_primary["ARC_PLAN_PRIMARY_REGION_INCLUDED"]["verdict"] == "FAIL"
    unknown = check(plan, [{"path": "/properties/Regions", "state": "UNRESOLVED"}, primary])
    assert unknown["ARC_PLAN_DISTINCT_REGIONS"]["verdict"] == "NEEDS_REVIEW"
    assert unknown["ARC_PLAN_PRIMARY_REGION_INCLUDED"]["verdict"] == "NEEDS_REVIEW"


def test_zonal_autoshift_requires_practice_run():
    resource = "AWS::ARCZonalShift::ZonalAutoshiftConfiguration"
    status = known("/properties/ZonalAutoshiftStatus", "ENABLED", "enabled")
    rule = "ARC_ZONAL_AUTOSHIFT_PRACTICE_RUN"
    assert check(resource, [status])[rule]["verdict"] == "FAIL"
    practice = known("/properties/PracticeRunConfiguration", {}, "practice")
    assert check(resource, [status, practice])[rule]["verdict"] == "PASS"
    assert check(resource, [status, {"path": practice["path"], "state": "UNRESOLVED"}])[rule]["verdict"] == "NEEDS_REVIEW"
    assert check(resource, [practice])[rule]["verdict"] == "NOT_APPLICABLE"
