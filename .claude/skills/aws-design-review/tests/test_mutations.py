"""Seeded-defect evaluation: mutation operators and the findings diff."""
import json
from argparse import Namespace
from pathlib import Path

import pytest

from aws_design_sheet.cfn_template import import_template, load_template
from aws_design_sheet.checker import Checker
from scripts.evaluate_mutations import ours_findings, parse_checkov, strongest
from scripts.mutation_operators import OPERATORS, Context


ROOT = Path(__file__).resolve().parents[1]
SCOPE = {"account": "111111111111", "region": "ap-northeast-1"}
ARGS = Namespace(environment="prod", **SCOPE)

NETWORK = """
Resources:
  Vpc: {Type: AWS::EC2::VPC, Properties: {CidrBlock: 10.0.0.0/16}}
  Gateway: {Type: AWS::EC2::InternetGateway}
  Attach:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties: {VpcId: !Ref Vpc, InternetGatewayId: !Ref Gateway}
  Public:
    Type: AWS::EC2::Subnet
    Properties: {VpcId: !Ref Vpc, CidrBlock: 10.0.1.0/24, AvailabilityZone: ap-northeast-1a}
  Private:
    Type: AWS::EC2::Subnet
    Properties: {VpcId: !Ref Vpc, CidrBlock: 10.0.2.0/24, AvailabilityZone: ap-northeast-1c}
  PublicTable: {Type: AWS::EC2::RouteTable, Properties: {VpcId: !Ref Vpc}}
  PrivateTable: {Type: AWS::EC2::RouteTable, Properties: {VpcId: !Ref Vpc}}
  PublicRoute:
    Type: AWS::EC2::Route
    DependsOn: Attach
    Properties: {RouteTableId: !Ref PublicTable, DestinationCidrBlock: 0.0.0.0/0, GatewayId: !Ref Gateway}
  PublicAssoc:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties: {SubnetId: !Ref Public, RouteTableId: !Ref PublicTable}
  PrivateAssoc:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties: {SubnetId: !Ref Private, RouteTableId: !Ref PrivateTable}
  NatIp: {Type: AWS::EC2::EIP, DependsOn: Attach, Properties: {Domain: vpc}}
  Nat:
    Type: AWS::EC2::NatGateway
    Properties: {SubnetId: !Ref Public, AllocationId: !GetAtt NatIp.AllocationId}
  PrivateRoute:
    Type: AWS::EC2::Route
    Properties: {RouteTableId: !Ref PrivateTable, DestinationCidrBlock: 0.0.0.0/0, NatGatewayId: !Ref Nat}
"""


@pytest.fixture(scope="module")
def checker():
    return Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json", ROOT / "rules/ledger.json",
                   ROOT / "rules/ruleset.json", None)


def mutate(template: dict, operator_id: str):
    operator = next(op for op in OPERATORS if op.id == operator_id)
    return operator.apply(Context(template, **SCOPE))


def test_operator_ids_are_unique_and_documented():
    assert len({op.id for op in OPERATORS}) == len(OPERATORS)
    assert {op.kind for op in OPERATORS} == {"deploy", "security", "function"}
    assert all(op.basis.startswith("https://docs.aws.amazon.com/") for op in OPERATORS)


def test_network_operators_change_only_a_copy():
    template = load_template(NETWORK)
    original = json.dumps(template, sort_keys=True)
    outside = mutate(template, "NET_SUBNET_OUTSIDE_VPC")
    assert outside.targets == ["Public"]
    assert outside.template["Resources"]["Public"]["Properties"]["CidrBlock"] == "10.1.1.0/24"
    overlap = mutate(template, "NET_SUBNET_OVERLAP")
    assert overlap.targets == ["Private", "Public"]
    assert overlap.template["Resources"]["Private"]["Properties"]["CidrBlock"] == "10.0.1.0/24"
    nat = mutate(template, "NET_NAT_IN_PRIVATE_SUBNET")
    assert nat.template["Resources"]["Nat"]["Properties"]["SubnetId"] == {"Ref": "Private"}
    route = mutate(template, "NET_ROUTE_GATEWAY_DEPENDENCY")
    assert "DependsOn" not in route.template["Resources"]["PublicRoute"]
    private_igw = mutate(template, "NET_PRIVATE_ROUTE_TO_IGW")
    assert private_igw.template["Resources"]["PrivateRoute"]["Properties"] == {
        "RouteTableId": {"Ref": "PrivateTable"}, "DestinationCidrBlock": "0.0.0.0/0",
        "GatewayId": {"Ref": "Gateway"}}
    assert json.dumps(template, sort_keys=True) == original


def test_operator_without_eligible_place_returns_none():
    template = load_template(NETWORK)
    assert mutate(template, "LAMBDA_TIMEOUT_OVER_LIMIT") is None
    assert mutate(template, "ELB_ALB_SINGLE_SUBNET") is None


def test_new_findings_on_targets_detect_the_defect(checker):
    template = load_template(NETWORK)
    base = ours_findings(checker, json.dumps(template), "net", ARGS)
    mutation = mutate(template, "NET_SUBNET_OUTSIDE_VPC")
    mutant = ours_findings(checker, json.dumps(mutation.template), "net", ARGS)
    hits = {key for key in mutant - base if key[0] in mutation.targets}
    assert strongest(hits, {"FAIL": 0, "NEEDS_REVIEW": 1}) == "FAIL"
    assert ("Public", "CIDR_CONTAINMENT", "/properties/CidrBlock", "FAIL") in hits
    assert strongest(set(), {"FAIL": 0}) == "MISSED"


def test_subnet_vpc_reference_to_another_type_needs_review_in_rds_check(checker):
    # A subnet whose VpcId names a security group used to crash the DB subnet group check.
    template = load_template(NETWORK.replace(
        "Properties: {VpcId: !Ref Vpc, CidrBlock: 10.0.2.0/24",
        "Properties: {VpcId: !Ref PublicTable, CidrBlock: 10.0.2.0/24") + """
  Group:
    Type: AWS::RDS::DBSubnetGroup
    Properties: {DBSubnetGroupDescription: db, SubnetIds: [!Ref Public, !Ref Private]}
""")
    design, _ = import_template(json.dumps(template), "net", project="p", environment="prod",
                                reference_catalog=checker.reference_types, **SCOPE)
    results = checker.check(design)["results"]
    assert [r["verdict"] for r in results if r["rule_id"] == "RDS_SUBNET_VPC"] == ["NEEDS_REVIEW"]
    assert "FAIL" in [r["verdict"] for r in results
                      if r["rule_id"] == "REFERENCE" and r["path"] == "/properties/VpcId"]


def test_checkov_paths_from_windows_match_mutant_files():
    output = json.dumps({"check_type": "cloudformation", "results": {"failed_checks": [
        {"check_id": "CKV_AWS_62", "file_path": "/000\\IAM_ROLE_ADMIN_WILDCARD.json",
         "resource": "AWS::IAM::Role.AppRole"}]}})
    assert parse_checkov("noise\n" + output) == {
        ("000/IAM_ROLE_ADMIN_WILDCARD.json", "AppRole"): {"CKV_AWS_62"}}
