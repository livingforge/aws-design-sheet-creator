"""Explicit subnet association VPC checks."""
import hashlib
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Relation, Resource, Scope, ValueState
from aws_design_sheet.checks.ec2.association import evaluate_ec2_subnet_association_vpc


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")
ROOT = Path(__file__).resolve().parents[1]


def field(path, value):
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def link(name, source, path, target):
    return Relation(id=name, source_resource_id=source, source_path=path,
                    target_resource_id=target, evidence_ids=["e1"])


def case(association_type, other_vpc="vpc-a"):
    second_name, second_type = (("RouteTableId", "AWS::EC2::RouteTable")
                                if association_type == "AWS::EC2::SubnetRouteTableAssociation"
                                else ("NetworkAclId", "AWS::EC2::NetworkAcl"))
    resources = [
        Resource(id="assoc", type=association_type, name="assoc", scope=SCOPE,
                 fields=[field("/properties/SubnetId", "subnet"),
                         field("/properties/" + second_name, "other")]),
        Resource(id="subnet", type="AWS::EC2::Subnet", name="subnet", scope=SCOPE,
                 fields=[field("/properties/VpcId", "vpc-a")]),
        Resource(id="other", type=second_type, name="other", scope=SCOPE,
                 fields=[field("/properties/VpcId", other_vpc)]),
        Resource(id="vpc-a", type="AWS::EC2::VPC", name="vpc-a", scope=SCOPE),
        Resource(id="vpc-b", type="AWS::EC2::VPC", name="vpc-b", scope=SCOPE),
    ]
    relations = [link("subnet", "assoc", "/properties/SubnetId", "subnet"),
                 link("other", "assoc", "/properties/" + second_name, "other"),
                 link("subnet-vpc", "subnet", "/properties/VpcId", "vpc-a"),
                 link("other-vpc", "other", "/properties/VpcId", other_vpc)]
    text = "EC2 association design"
    design = Design(project="pilot", environment="prod", account=SCOPE.account,
                    documents=[Document(id="d1", name="input", version="1", text=text,
                                        sha256=hashlib.sha256(text.encode()).hexdigest())],
                    evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                       excerpt=text)], resources=resources, relations=relations)
    return design, resources[0], second_name


@pytest.mark.parametrize("association_type", [
    "AWS::EC2::SubnetRouteTableAssociation", "AWS::EC2::SubnetNetworkAclAssociation"])
def test_known_same_and_different_vpc(association_type):
    design, association, second_name = case(association_type)
    result = evaluate_ec2_subnet_association_vpc(design, association)
    assert result["verdict"] == "PASS"
    assert result["path"] == "/properties/" + second_name
    assert result["evidence_ids"] == ["e1"]

    design, association, _ = case(association_type, "vpc-b")
    assert evaluate_ec2_subnet_association_vpc(design, association)["verdict"] == "FAIL"


@pytest.mark.parametrize("association_type", [
    "AWS::EC2::SubnetRouteTableAssociation", "AWS::EC2::SubnetNetworkAclAssociation"])
def test_external_or_conflicting_reference_stays_unresolved(association_type):
    design, association, second_name = case(association_type)
    design.relations = [relation for relation in design.relations if relation.id != "other-vpc"]
    result = evaluate_ec2_subnet_association_vpc(design, association)
    assert result["verdict"] == "NEEDS_REVIEW"
    assert "/properties/" + second_name + " -> other/properties/VpcId" in result["dependencies"]

    design, association, _ = case(association_type)
    design.relations.append(link("conflict", "assoc", "/properties/SubnetId", "subnet"))
    assert evaluate_ec2_subnet_association_vpc(design, association)["verdict"] == "NEEDS_REVIEW"


def test_checker_runs_subnet_association_vpc_check():
    design, _, _ = case("AWS::EC2::SubnetRouteTableAssociation", "vpc-b")
    findings = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(design)["results"]
    assert [item["verdict"] for item in findings
            if item["rule_id"] == "EC2_SUBNET_ROUTE_TABLE_SAME_VPC"] == ["FAIL"]
