"""RDS EventSubscription SourceIds type checks."""
import hashlib
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Relation, Resource, Scope, ValueState
from aws_design_sheet.checks.rds.event_source import evaluate_rds_event_source_type


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")
ROOT = Path(__file__).resolve().parents[1]


def field(path, value):
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def make_case(source_type="db-instance", target_type="AWS::RDS::DBInstance", linked=True):
    subscription = Resource(id="subscription", type="AWS::RDS::EventSubscription",
                            name="subscription", scope=SCOPE,
                            fields=[field("/properties/SourceType", source_type),
                                    field("/properties/SourceIds", ["db"]),
                                    field("/properties/SnsTopicArn", "arn:aws:sns:ap-northeast-1:111111111111:topic")])
    target = Resource(id="db", type=target_type, name="db", scope=SCOPE)
    text = "RDS event subscription"
    design = Design(project="pilot", environment="prod", account=SCOPE.account,
                    documents=[Document(id="d1", name="input", version="1", text=text,
                                        sha256=hashlib.sha256(text.encode()).hexdigest())],
                    evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                       excerpt=text)], resources=[subscription, target],
                    relations=([Relation(id="source", source_resource_id="subscription",
                                        source_path="/properties/SourceIds/0", target_resource_id="db",
                                        evidence_ids=["e1"])] if linked else []))
    return design, subscription


@pytest.mark.parametrize("source_type,target_type", [
    ("db-instance", "AWS::RDS::DBInstance"),
    ("db-cluster", "AWS::RDS::DBCluster"),
    ("db-parameter-group", "AWS::RDS::DBParameterGroup"),
    ("db-security-group", "AWS::RDS::DBSecurityGroup"),
    ("db-proxy", "AWS::RDS::DBProxy"),
])
def test_matching_explicit_reference_passes(source_type, target_type):
    design, subscription = make_case(source_type, target_type)
    result = evaluate_rds_event_source_type(design, subscription)
    assert result["verdict"] == "PASS"
    assert result["rule_id"] == "RDS_EVENT_SUBSCRIPTION_SOURCE_TYPE"
    assert result["evidence_ids"] == ["e1"]


def test_mismatched_reference_fails():
    design, subscription = make_case("db-cluster", "AWS::RDS::DBInstance")
    assert evaluate_rds_event_source_type(design, subscription)["verdict"] == "FAIL"


def test_physical_id_and_unresolved_source_type_need_review():
    design, subscription = make_case(linked=False)
    result = evaluate_rds_event_source_type(design, subscription)
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == ["/properties/SourceIds/0"]

    design, subscription = make_case()
    subscription.fields[0] = FieldValue(path="/properties/SourceType", state=ValueState.UNRESOLVED)
    assert evaluate_rds_event_source_type(design, subscription)["verdict"] == "NEEDS_REVIEW"


def test_no_source_ids_is_not_applicable():
    design, subscription = make_case()
    subscription.fields = [f for f in subscription.fields if f.path != "/properties/SourceIds"]
    design.relations = []
    assert evaluate_rds_event_source_type(design, subscription)["verdict"] == "NOT_APPLICABLE"


def test_checker_runs_rds_event_source_type_check():
    design, _ = make_case("db-cluster", "AWS::RDS::DBInstance")
    findings = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(design)["results"]
    assert [row["verdict"] for row in findings
            if row["rule_id"] == "RDS_EVENT_SUBSCRIPTION_SOURCE_TYPE"] == ["FAIL"]
