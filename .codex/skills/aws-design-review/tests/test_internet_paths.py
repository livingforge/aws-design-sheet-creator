"""Internet paths through route tables: NAT gateway and internet-facing load balancer subnets."""
from pathlib import Path

import pytest

from aws_design_sheet.cfn_template import import_template
from aws_design_sheet.checker import Checker


ROOT = Path(__file__).resolve().parents[1]
SCOPE = {"account": "111111111111", "region": "ap-northeast-1"}

NETWORK = """
Resources:
  Vpc: {Type: AWS::EC2::VPC, Properties: {CidrBlock: 10.0.0.0/16}}
  Gateway: {Type: AWS::EC2::InternetGateway}
  Attach:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties: {VpcId: !Ref Vpc, InternetGatewayId: !Ref Gateway}
  PublicA: {Type: AWS::EC2::Subnet, Properties: {VpcId: !Ref Vpc, CidrBlock: 10.0.1.0/24}}
  PublicC: {Type: AWS::EC2::Subnet, Properties: {VpcId: !Ref Vpc, CidrBlock: 10.0.2.0/24}}
  PrivateA: {Type: AWS::EC2::Subnet, Properties: {VpcId: !Ref Vpc, CidrBlock: 10.0.3.0/24}}
  PrivateC: {Type: AWS::EC2::Subnet, Properties: {VpcId: !Ref Vpc, CidrBlock: 10.0.4.0/24}}
  Loose: {Type: AWS::EC2::Subnet, Properties: {VpcId: !Ref Vpc, CidrBlock: 10.0.5.0/24}}
  PublicTable: {Type: AWS::EC2::RouteTable, Properties: {VpcId: !Ref Vpc}}
  PrivateTable: {Type: AWS::EC2::RouteTable, Properties: {VpcId: !Ref Vpc}}
  PublicRoute:
    Type: AWS::EC2::Route
    DependsOn: Attach
    Properties: {RouteTableId: !Ref PublicTable, DestinationCidrBlock: 0.0.0.0/0, GatewayId: !Ref Gateway}
  PublicAssocA:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties: {SubnetId: !Ref PublicA, RouteTableId: !Ref PublicTable}
  PublicAssocC:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties: {SubnetId: !Ref PublicC, RouteTableId: !Ref PublicTable}
  PrivateAssocA:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties: {SubnetId: !Ref PrivateA, RouteTableId: !Ref PrivateTable}
  PrivateAssocC:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties: {SubnetId: !Ref PrivateC, RouteTableId: !Ref PrivateTable}
  NatIp: {Type: AWS::EC2::EIP, DependsOn: Attach, Properties: {Domain: vpc}}
  Nat:
    Type: AWS::EC2::NatGateway
    Properties: {SubnetId: !Ref PublicA, AllocationId: !GetAtt NatIp.AllocationId}
  PrivateRoute:
    Type: AWS::EC2::Route
    Properties: {RouteTableId: !Ref PrivateTable, DestinationCidrBlock: 0.0.0.0/0, NatGatewayId: !Ref Nat}
  Balancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties: {Subnets: [!Ref PublicA, !Ref PublicC]}
"""


@pytest.fixture(scope="module")
def checker():
    return Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json")


def verdicts(checker, text, rule_id):
    design, _ = import_template(text, "t", project="p", environment="prod", **SCOPE)
    names = {resource.id: resource.name for resource in design.resources}
    return {names[r["resource_id"]]: (r["verdict"], r["severity"]) for r in checker.check(design)["results"]
            if r["rule_id"] == rule_id}


def test_working_network_passes(checker):
    assert verdicts(checker, NETWORK, "EC2_NAT_GATEWAY_PUBLIC_SUBNET") == {"Nat": ("PASS", "ERROR")}
    assert verdicts(checker, NETWORK, "EC2_NAT_GATEWAY_ROUTED") == {"Nat": ("PASS", "WARNING")}
    assert verdicts(checker, NETWORK, "ELB_INTERNET_FACING_PUBLIC_SUBNETS") == {"Balancer": ("PASS", "ERROR")}


def test_nat_gateway_in_subnet_without_internet_route_fails(checker):
    text = NETWORK.replace("Properties: {SubnetId: !Ref PublicA, AllocationId",
                           "Properties: {SubnetId: !Ref PrivateA, AllocationId")
    assert verdicts(checker, text, "EC2_NAT_GATEWAY_PUBLIC_SUBNET") == {"Nat": ("FAIL", "ERROR")}


def test_subnet_on_main_route_table_needs_review(checker):
    text = NETWORK.replace("Properties: {SubnetId: !Ref PublicA, AllocationId",
                           "Properties: {SubnetId: !Ref Loose, AllocationId")
    assert verdicts(checker, text, "EC2_NAT_GATEWAY_PUBLIC_SUBNET") == {"Nat": ("NEEDS_REVIEW", "ERROR")}


def test_private_nat_gateway_needs_no_internet_route(checker):
    text = NETWORK.replace("Properties: {SubnetId: !Ref PublicA, AllocationId: !GetAtt NatIp.AllocationId}",
                           "Properties: {SubnetId: !Ref PrivateA, ConnectivityType: private}")
    assert verdicts(checker, text, "EC2_NAT_GATEWAY_PUBLIC_SUBNET") == {"Nat": ("NOT_APPLICABLE", "ERROR")}


def test_nat_gateway_without_routes_warns(checker):
    text = NETWORK.replace("DestinationCidrBlock: 0.0.0.0/0, NatGatewayId: !Ref Nat",
                           "DestinationCidrBlock: 0.0.0.0/0, GatewayId: !Ref Gateway")
    assert verdicts(checker, text, "EC2_NAT_GATEWAY_ROUTED") == {"Nat": ("FAIL", "WARNING")}


@pytest.mark.parametrize("balancer, verdict", [
    ("Properties: {Subnets: [!Ref PrivateA, !Ref PrivateC]}", "FAIL"),
    ("Properties: {Subnets: [!Ref PublicA, !Ref PrivateC]}", "FAIL"),
    ("Properties: {Subnets: [!Ref PublicA, !Ref Loose]}", "NEEDS_REVIEW"),
    ("Properties: {Scheme: internal, Subnets: [!Ref PrivateA, !Ref PrivateC]}", "NOT_APPLICABLE"),
    ("Properties: {SubnetMappings: [{SubnetId: !Ref PrivateA}, {SubnetId: !Ref PublicC}], Type: network}", "FAIL"),
])
def test_internet_facing_load_balancer_subnets(checker, balancer, verdict):
    text = NETWORK.replace("Properties: {Subnets: [!Ref PublicA, !Ref PublicC]}", balancer)
    assert verdicts(checker, text, "ELB_INTERNET_FACING_PUBLIC_SUBNETS") == {"Balancer": (verdict, "ERROR")}


def test_classic_load_balancer_without_subnets_is_not_applicable(checker):
    text = NETWORK + """
  Classic:
    Type: AWS::ElasticLoadBalancing::LoadBalancer
    Properties:
      AvailabilityZones: [ap-northeast-1a]
      Listeners: [{LoadBalancerPort: "80", InstancePort: "80", Protocol: HTTP}]
"""
    assert verdicts(checker, text, "ELB_INTERNET_FACING_PUBLIC_SUBNETS")["Classic"] == ("NOT_APPLICABLE", "ERROR")
