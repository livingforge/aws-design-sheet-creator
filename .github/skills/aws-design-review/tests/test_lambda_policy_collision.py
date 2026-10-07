import hashlib
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import (Candidate, Design, Document, Evidence, FieldValue,
                                     Relation, Resource, Scope, ValueState)
from aws_design_sheet.checks.lambda_.policy_collision import evaluate_lambda_permission_policy_collision as evaluate


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")
ARN = "arn:aws:lambda:ap-northeast-1:111111111111:function:orders"


def field(path, value):
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def resource(type_name, name, path=None, value=None):
    return Resource(id=name, type=type_name, name=name, scope=SCOPE,
                    fields=[field(path, value)] if path else [])


def case(permission, *others, relations=()):
    text = "Lambda policy design"
    return Design(project="pilot", environment="prod", account=SCOPE.account,
                  documents=[Document(id="d1", name="input", version="1", text=text,
                                      sha256=hashlib.sha256(text.encode()).hexdigest())],
                  evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                     excerpt=text)], resources=[permission, *others], relations=list(relations))


def test_literal_names_and_arns_detect_same_function():
    permission = resource("AWS::Lambda::Permission", "permission", "/properties/FunctionName", "orders")
    policy = resource("AWS::Lambda::ResourcePolicy", "policy", "/properties/ResourceArn", ARN)
    result = evaluate(case(permission, policy), permission)
    assert result["verdict"] == "FAIL"
    assert result["rule_id"] == "LAMBDA_PERMISSION_RESOURCE_POLICY_COLLISION"
    assert result["evidence_ids"] == ["e1"]


def test_different_functions_and_qualifiers_pass():
    permission = resource("AWS::Lambda::Permission", "permission", "/properties/FunctionName", "orders")
    policy = resource("AWS::Lambda::ResourcePolicy", "policy", "/properties/ResourceArn",
                      ARN.replace(":orders", ":billing"))
    assert evaluate(case(permission, policy), permission)["verdict"] == "PASS"
    policy.fields[0] = field("/properties/ResourceArn", ARN + ":prod")
    assert evaluate(case(permission, policy), permission)["verdict"] == "PASS"


def test_logical_references_detect_same_or_distinct_targets():
    permission = resource("AWS::Lambda::Permission", "permission")
    policy = resource("AWS::Lambda::ResourcePolicy", "policy")
    function_a = resource("AWS::Lambda::Function", "function-a")
    function_b = resource("AWS::Lambda::Function", "function-b")
    permission_ref = Relation(id="p-ref", source_resource_id="permission",
                              source_path="/properties/FunctionName", target_resource_id="function-a",
                              evidence_ids=["e1"])
    policy_ref = Relation(id="r-ref", source_resource_id="policy",
                          source_path="/properties/ResourceArn", target_resource_id="function-a",
                          evidence_ids=["e1"])
    design = case(permission, policy, function_a, function_b, relations=[permission_ref, policy_ref])
    assert evaluate(design, permission)["verdict"] == "FAIL"
    policy_ref.target_resource_id = "function-b"
    assert evaluate(design, permission)["verdict"] == "PASS"


def test_explicit_function_name_bridges_reference_to_literal_arn():
    permission = resource("AWS::Lambda::Permission", "permission")
    policy = resource("AWS::Lambda::ResourcePolicy", "policy", "/properties/ResourceArn", ARN)
    function = resource("AWS::Lambda::Function", "function", "/properties/FunctionName", "orders")
    relation = Relation(id="ref", source_resource_id="permission",
                        source_path="/properties/FunctionName", target_resource_id="function",
                        evidence_ids=["e1"])
    assert evaluate(case(permission, policy, function, relations=[relation]), permission)["verdict"] == "FAIL"


def test_unresolved_reference_and_literal_require_review():
    permission = resource("AWS::Lambda::Permission", "permission")
    policy = resource("AWS::Lambda::ResourcePolicy", "policy", "/properties/ResourceArn", ARN)
    permission.fields = [FieldValue(path="/properties/FunctionName", state=ValueState.UNRESOLVED)]
    result = evaluate(case(permission, policy), permission)
    assert result["verdict"] == "NEEDS_REVIEW"
    permission.fields = []
    function = resource("AWS::Lambda::Function", "function")
    relation = Relation(id="ref", source_resource_id="permission",
                        source_path="/properties/FunctionName", target_resource_id="function",
                        evidence_ids=["e1"])
    assert evaluate(case(permission, policy, function, relations=[relation]), permission)["verdict"] == "NEEDS_REVIEW"


def test_no_resource_policy_is_not_applicable():
    permission = resource("AWS::Lambda::Permission", "permission", "/properties/FunctionName", "orders")
    assert evaluate(case(permission), permission)["verdict"] == "NOT_APPLICABLE"


def test_checker_reports_policy_collision():
    permission = resource("AWS::Lambda::Permission", "permission", "/properties/FunctionName", "orders")
    policy = resource("AWS::Lambda::ResourcePolicy", "policy", "/properties/ResourceArn", ARN)
    root = Path(__file__).resolve().parents[1]
    report = Checker(root / "schemas", root / "profiles/vpc-subnet.json").check(case(permission, policy))
    findings = [row for row in report["results"]
                if row["rule_id"] == "LAMBDA_PERMISSION_RESOURCE_POLICY_COLLISION"]
    assert len(findings) == 1
    assert findings[0]["verdict"] == "FAIL"
