import hashlib

from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Relation, Resource, Scope, ValueState
from aws_design_sheet.pilot_rules import (evaluate_elbv2_secure_listener_certificate,
                                          evaluate_iam_policy_attachment)


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")


def field(path, value):
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def design(*resources, relations=()):
    source = "design evidence"
    return Design(project="pilot", environment="prod", account=SCOPE.account,
                  documents=[Document(id="d1", name="input", version="1", text=source,
                                      sha256=hashlib.sha256(source.encode()).hexdigest())],
                  evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                     excerpt=source)], resources=list(resources), relations=list(relations))


def resource(type_name, *fields, id="subject"):
    return Resource(id=id, type=type_name, name=id, scope=SCOPE, fields=list(fields))


def test_iam_attachment_known_empty_unresolved_and_non_applicable():
    policy = resource("AWS::IAM::Policy", field("/properties/Roles", ["app-role"]))
    assert evaluate_iam_policy_attachment(design(policy), policy)["verdict"] == "PASS"
    assert evaluate_iam_policy_attachment(design(policy), policy)["evidence_ids"] == ["e1"]
    empty = resource("AWS::IAM::Policy", field("/properties/Roles", []))
    assert evaluate_iam_policy_attachment(design(empty), empty)["verdict"] == "FAIL"
    unresolved = resource("AWS::IAM::Policy", FieldValue(path="/properties/Roles", state=ValueState.UNRESOLVED))
    result = evaluate_iam_policy_attachment(design(unresolved), unresolved)
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == ["/properties/Roles"]
    unrelated = resource("AWS::IAM::Role")
    assert evaluate_iam_policy_attachment(design(unrelated), unrelated)["verdict"] == "NOT_APPLICABLE"


def test_iam_attachment_relation_and_unresolved_relation():
    policy = resource("AWS::IAM::Policy")
    role = resource("AWS::IAM::Role", id="role")
    relation = Relation(id="r1", source_resource_id=policy.id, source_path="/properties/Roles/0",
                        target_resource_id=role.id, evidence_ids=["e1"])
    assert evaluate_iam_policy_attachment(design(policy, role, relations=[relation]), policy)["verdict"] == "PASS"
    relation.target_resource_id = "missing"
    result = evaluate_iam_policy_attachment(design(policy, role, relations=[relation]), policy)
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == ["/properties/Roles/0"]


def test_elbv2_secure_listener_certificates():
    protocol = field("/properties/Protocol", "HTTPS")
    listener = resource("AWS::ElasticLoadBalancingV2::Listener", protocol,
                        field("/properties/Certificates", [{"CertificateArn": "arn:aws:acm:ap-northeast-1:111111111111:certificate/example"}]))
    assert evaluate_elbv2_secure_listener_certificate(design(listener), listener)["verdict"] == "PASS"
    listener.fields[1] = field("/properties/Certificates", [])
    assert evaluate_elbv2_secure_listener_certificate(design(listener), listener)["verdict"] == "FAIL"
    listener.fields[1] = field("/properties/Certificates", [{"CertificateArn": "a"}, {"CertificateArn": "b"}])
    assert evaluate_elbv2_secure_listener_certificate(design(listener), listener)["verdict"] == "FAIL"
    listener.fields[1] = FieldValue(path="/properties/Certificates", state=ValueState.UNRESOLVED)
    result = evaluate_elbv2_secure_listener_certificate(design(listener), listener)
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == ["/properties/Certificates"]
    listener.fields[0] = field("/properties/Protocol", "HTTP")
    assert evaluate_elbv2_secure_listener_certificate(design(listener), listener)["verdict"] == "NOT_APPLICABLE"


def test_elbv2_does_not_require_ssl_policy_and_accepts_nested_reference():
    listener = resource("AWS::ElasticLoadBalancingV2::Listener",
                        field("/properties/Protocol", "TLS"),
                        field("/properties/Certificates", [{}]))
    ref = Relation(id="cert", source_resource_id=listener.id,
                   source_path="/properties/Certificates/0/CertificateArn",
                   unresolved_name="external-cert", evidence_ids=["e1"])
    assert evaluate_elbv2_secure_listener_certificate(design(listener, relations=[ref]), listener)["verdict"] == "PASS"
    result = evaluate_elbv2_secure_listener_certificate(design(listener), listener)
    assert result["verdict"] == "NEEDS_REVIEW"
