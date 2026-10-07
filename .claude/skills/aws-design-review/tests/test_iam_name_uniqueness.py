import hashlib
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import (Candidate, Design, Document, Evidence, FieldValue,
                                     Resource, Scope, ValueState)
from aws_design_sheet.checks.iam.name_uniqueness import evaluate_iam_explicit_name_uniqueness as evaluate


CASES = [("Group", "GroupName"), ("Role", "RoleName"), ("User", "UserName")]


def field(name, value):
    path = "/properties/" + name
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def resource(kind, id, physical, account="111111111111", region="ap-northeast-1"):
    scope = Scope(environment="prod", account=account, region=region)
    return Resource(id=id, type="AWS::IAM::" + kind, name=id, scope=scope,
                    fields=[field(kind + "Name", physical)] if physical is not None else [])


def case(*resources):
    text = "IAM naming design"
    return Design(project="pilot", environment="prod", account="111111111111",
                  documents=[Document(id="d1", name="input", version="1", text=text,
                                      sha256=hashlib.sha256(text.encode()).hexdigest())],
                  evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                     excerpt=text)], resources=list(resources))


@pytest.mark.parametrize("kind,property_name", CASES)
def test_case_insensitive_physical_name_collision(kind, property_name):
    first = resource(kind, "logical-a", "Admins")
    second = resource(kind, "logical-b", "admins", region="us-east-1")
    design = case(first, second)
    result = evaluate(design, first)
    assert result["verdict"] == "FAIL"
    assert result["path"] == "/properties/" + property_name
    assert result["evidence_ids"] == ["e1"]
    assert evaluate(design, second)["verdict"] == "FAIL"


@pytest.mark.parametrize("kind,property_name", CASES)
def test_single_explicit_name_requires_account_review(kind, property_name):
    first = resource(kind, "logical", "Admins")
    result = evaluate(case(first), first)
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == ["/properties/" + property_name]


def test_different_account_or_type_does_not_make_design_collision():
    first = resource("Role", "role-a", "Admins")
    other_account = resource("Role", "role-b", "admins", account="222222222222")
    other_type = resource("User", "user-a", "admins")
    result = evaluate(case(first, other_account, other_type), first)
    assert result["verdict"] == "NEEDS_REVIEW"


def test_generated_and_unresolved_names():
    generated = resource("Group", "group", None)
    assert evaluate(case(generated), generated)["verdict"] == "NOT_APPLICABLE"
    unresolved = resource("Group", "group2", None)
    unresolved.fields = [FieldValue(path="/properties/GroupName", state=ValueState.UNRESOLVED)]
    assert evaluate(case(unresolved), unresolved)["verdict"] == "NEEDS_REVIEW"


def test_checker_includes_iam_name_check():
    first = resource("Group", "logical-a", "Admins")
    second = resource("Group", "logical-b", "admins")
    root = Path(__file__).resolve().parents[1]
    report = Checker(root / "schemas", root / "profiles/vpc-subnet.json").check(case(first, second))
    findings = [row for row in report["results"] if row["rule_id"] == "IAM_EXPLICIT_NAME_ACCOUNT_UNIQUE"]
    assert len(findings) == 2
    assert all(row["verdict"] == "FAIL" for row in findings)
