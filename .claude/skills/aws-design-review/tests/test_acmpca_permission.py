import json
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Design


ROOT = Path(__file__).resolve().parents[1]


def _run(value, state="KNOWN"):
    data = json.loads((ROOT / "examples/valid.json").read_text(encoding="utf-8"))
    field = {"path": "/properties/Principal", "state": state}
    if state == "KNOWN":
        field.update(selected_candidate_id="principal", candidates=[
            {"id": "principal", "raw": str(value), "value": value, "evidence_ids": ["e-vpc"]}])
    elif state == "UNRESOLVED":
        field["candidates"] = []
    data["resources"].append({
        "id": "permission", "type": "AWS::ACMPCA::Permission", "name": "acm",
        "scope": data["resources"][0]["scope"], "fields": [field]})
    result = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(
        Design.model_validate(data))
    return next(item for item in result["results"]
                if item["rule_id"] == "ACMPCA_PERMISSION_PRINCIPAL")


def test_acmpca_permission_principal_rule():
    passed = _run("acm.amazonaws.com")
    assert passed["verdict"] == "PASS"
    assert passed["source_urls"] and passed["evidence_ids"] == ["e-vpc"]
    assert _run("ec2.amazonaws.com")["verdict"] == "FAIL"
    unresolved = _run(None, "UNRESOLVED")
    assert unresolved["verdict"] == "NEEDS_REVIEW"
    assert unresolved["dependencies"] == ["/properties/Principal"]
