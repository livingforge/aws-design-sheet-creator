import hashlib
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import (Candidate, Design, Document, Evidence, FieldValue,
                                     Resource, Scope, ValueState)
from aws_design_sheet.checks.iam.service_linked_role import evaluate_iam_service_linked_role_duplicate as evaluate


def field(name, value):
    path = "/properties/" + name
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=value, value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def role(identifier, service, suffix=None, account="111111111111", region="ap-northeast-1"):
    fields = [field("AWSServiceName", service)] if service is not None else []
    if suffix is not None:
        fields.append(field("CustomSuffix", suffix))
    return Resource(id=identifier, type="AWS::IAM::ServiceLinkedRole", name=identifier,
                    scope=Scope(environment="prod", account=account, region=region), fields=fields)


def design(*resources):
    content = "IAM service-linked role design"
    return Design(project="pilot", environment="prod", account="111111111111",
                  documents=[Document(id="d1", name="input", version="1", text=content,
                                      sha256=hashlib.sha256(content.encode()).hexdigest())],
                  evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                     excerpt=content)], resources=list(resources))


def test_duplicate_default_suffix_in_same_account_across_regions():
    first = role("first", "autoscaling.amazonaws.com")
    second = role("second", "autoscaling.amazonaws.com", region="us-east-1")
    case = design(first, second)
    assert evaluate(case, first)["verdict"] == "FAIL"
    assert evaluate(case, second)["verdict"] == "FAIL"


def test_same_service_with_different_suffix_requires_external_review():
    first = role("first", "autoscaling.amazonaws.com")
    second = role("second", "autoscaling.amazonaws.com", "debug")
    case = design(first, second)
    assert evaluate(case, first)["verdict"] == "NEEDS_REVIEW"
    assert evaluate(case, second)["verdict"] == "NEEDS_REVIEW"


def test_service_case_is_preserved_and_account_scope_is_respected():
    first = role("first", "service.amazonaws.com", "debug")
    other_case = role("second", "Service.amazonaws.com", "debug")
    other_account = role("third", "service.amazonaws.com", "debug", account="222222222222")
    assert evaluate(design(first, other_case, other_account), first)["verdict"] == "NEEDS_REVIEW"


def test_unresolved_service_needs_review():
    item = role("first", None)
    result = evaluate(design(item), item)
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == ["/properties/AWSServiceName", "/properties/CustomSuffix"]


def test_checker_includes_service_linked_role_duplicate():
    first = role("first", "autoscaling.amazonaws.com")
    second = role("second", "autoscaling.amazonaws.com")
    root = Path(__file__).resolve().parents[1]
    report = Checker(root / "schemas", root / "profiles/vpc-subnet.json").check(design(first, second))
    findings = [row for row in report["results"]
                if row["rule_id"] == "IAM_SERVICE_LINKED_ROLE_DUPLICATE_REQUEST"]
    assert len(findings) == 2
    assert all(row["verdict"] == "FAIL" for row in findings)
