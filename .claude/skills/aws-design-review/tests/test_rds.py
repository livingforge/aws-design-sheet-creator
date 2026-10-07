import hashlib
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.extractor import LineExtractor, TextSource
from aws_design_sheet.models import Design

ROOT = Path(__file__).resolve().parents[1]


def test_rds_relationships_and_azs():
    text = (ROOT / "examples/rds-network.txt").read_text(encoding="utf-8")
    design = LineExtractor().extract([TextSource(id="doc-1", name="rds-network.txt", version="1", text=text)],
                                     project="rds", environment="prod", account="1", region="ap-northeast-1")
    result = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(design)
    assert len(design.resources) == 6
    assert len(design.relations) == 7
    assert not [r for r in result["results"] if r["verdict"] == "FAIL"]
    assert any(r["rule_id"] == "RDS_SUBNET_AZ" and r["verdict"] == "PASS" for r in result["results"])
    assert any(r["rule_id"] == "RDS_SECURITY_GROUP_VPC" and r["verdict"] == "PASS"
               for r in result["results"])


def test_rds_same_az_violation():
    text = (ROOT / "examples/rds-network.txt").read_text(encoding="utf-8").replace(
        "private-c: Vpc=main; CidrBlock=10.0.2.0/24; AvailabilityZone=ap-northeast-1c",
        "private-c: Vpc=main; CidrBlock=10.0.2.0/24; AvailabilityZone=ap-northeast-1a")
    design = LineExtractor().extract([TextSource(id="doc-1", name="rds-network.txt", version="1", text=text)],
                                     project="rds", environment="prod", account="1", region="ap-northeast-1")
    result = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(design)
    assert any(r["rule_id"] == "RDS_SUBNET_AZ" and r["verdict"] == "FAIL" for r in result["results"])


def test_rds_security_group_in_other_vpc():
    text = (ROOT / "examples/rds-network.txt").read_text(encoding="utf-8")
    text = text.replace("SecurityGroup db-sg: Vpc=main", "VPC other: CidrBlock=10.1.0.0/16\nSecurityGroup db-sg: Vpc=other")
    design = LineExtractor().extract([TextSource(id="doc-1", name="rds-network.txt", version="1", text=text)],
                                     project="rds", environment="prod", account="1", region="ap-northeast-1")
    result = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(design)
    assert any(r["rule_id"] == "RDS_SECURITY_GROUP_VPC" and r["verdict"] == "FAIL"
               for r in result["results"])


def test_duplicate_security_group_reference():
    text = (ROOT / "examples/rds-network.txt").read_text(encoding="utf-8").replace(
        'SecurityGroups=["db-sg"]', 'SecurityGroups=["db-sg","db-sg"]')
    design = LineExtractor().extract([TextSource(id="doc-1", name="rds-network.txt", version="1", text=text)],
                                     project="rds", environment="prod", account="1", region="ap-northeast-1")
    result = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(design)
    assert any(r["rule_id"] == "SCHEMA_REFERENCE_UNIQUE" and r["verdict"] == "FAIL"
               for r in result["results"])


@pytest.mark.parametrize("fifo,linked,expected", [
    (True, True, "FAIL"),
    (False, True, "PASS"),
    (None, True, "PASS"),
    ("UNRESOLVED", True, "NEEDS_REVIEW"),
    (False, False, "NEEDS_REVIEW"),
])
def test_rds_event_subscription_requires_standard_sns_topic(fifo, linked, expected):
    scope = {"environment": "prod", "account": "111111111111", "region": "ap-northeast-1"}
    topic_fields = []
    if isinstance(fifo, bool):
        topic_fields.append({"path": "/properties/FifoTopic", "state": "KNOWN",
                             "selected_candidate_id": "fifo", "candidates": [{
                                 "id": "fifo", "raw": str(fifo).lower(), "value": fifo,
                                 "evidence_ids": ["e-1"]}]})
    elif fifo == "UNRESOLVED":
        topic_fields.append({"path": "/properties/FifoTopic", "state": "UNRESOLVED"})
    design = Design.model_validate({
        "project": "rds-event-topic", "environment": "prod", "account": scope["account"],
        "region": scope["region"],
        "documents": [{"id": "doc-1", "name": "design.txt", "version": "1",
                       "sha256": hashlib.sha256(b"topic fifo").hexdigest(), "text": "topic fifo"}],
        "evidence": [{"id": "e-1", "document_id": "doc-1", "start_line": 1,
                      "end_line": 1, "excerpt": "topic fifo"}],
        "resources": [
            {"id": "event-sub", "type": "AWS::RDS::EventSubscription", "name": "events",
             "scope": scope, "fields": [{"path": "/properties/SnsTopicArn", "state": "KNOWN",
                                    "selected_candidate_id": "arn", "candidates": [{
                                        "id": "arn", "raw": "topic", "value": "topic",
                                        "evidence_ids": ["e-1"]}]}]},
            {"id": "topic", "type": "AWS::SNS::Topic", "name": "topic",
             "scope": scope, "fields": topic_fields},
        ],
        "relations": ([{"id": "event-topic", "source_resource_id": "event-sub",
                       "source_path": "/properties/SnsTopicArn", "target_resource_id": "topic"}]
                      if linked else []),
    })
    results = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(design)["results"]
    verdicts = [r["verdict"] for r in results
                if r["rule_id"] == "RDS_EVENT_SUBSCRIPTION_SNS_STANDARD"]
    assert verdicts == [expected]
