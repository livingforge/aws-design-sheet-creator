"""CloudFormation template import used by the template-corpus evaluation."""
from pathlib import Path

import pytest

from aws_design_sheet.cfn_template import import_template, load_template, template_to_lines
from aws_design_sheet.extractor import TextSource
from aws_design_sheet.models import Relation, Resource, Scope, ValueState
from aws_design_sheet.rule_engine import _Context, _check, reference_view
from aws_design_sheet.runner import run_text
from scripts.evaluate_template_corpus import categorize, unique_templates


ROOT = Path(__file__).resolve().parents[1]
SCOPE = {"account": "111111111111", "region": "ap-northeast-1"}

TEMPLATE = """
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  Cidr: {Type: String, Default: 10.0.0.0/16}
  Size: {Type: Number, Default: "20"}
  Subnets: {Type: CommaDelimitedList, Default: "a, b"}
  KeyName: {Type: AWS::EC2::KeyPair::KeyName}
  Env: {Type: String, Default: prod}
Mappings:
  Region: {ap-northeast-1: {Ami: ami-123}}
Conditions:
  IsProd: !Equals [!Ref Env, prod]
  IsDev: !Not [!Condition IsProd]
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: !Ref Cidr
      Tags: [{Key: Name, Value: !Sub "${AWS::Region}-vpc"}]
  Attach:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties: {VpcId: !Ref Vpc, InternetGatewayId: !Ref Gateway}
  Gateway:
    Type: AWS::EC2::InternetGateway
  Subnet:
    Type: AWS::EC2::Subnet
    DependsOn: Attach
    Properties:
      VpcId: !GetAtt Vpc.VpcId
      CidrBlock: !Select [1, !Cidr [!Ref Cidr, 4, 8]]
      AvailabilityZone: !Select [0, !GetAZs ""]
      MapPublicIpOnLaunch: !If [IsProd, false, true]
      AssignIpv6AddressOnCreation: !Ref AWS::NoValue
  DevOnly:
    Type: AWS::SNS::Topic
    Condition: IsDev
  Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: !FindInMap [Region, !Ref "AWS::Region", Ami]
      KeyName: !Ref KeyName
      UserData: !Base64 {"Fn::Sub": "${Gateway.InternetGatewayId}"}
  Volume:
    Type: AWS::EC2::Volume
    Properties: {Size: !Ref Size, AvailabilityZone: ap-northeast-1a}
  Custom:
    Type: Custom::Lookup
"""


def convert(text=TEMPLATE):
    return import_template(text, "sample.yaml", project="p", environment="prod", **SCOPE)


def test_template_lines_resolve_defaults_and_keep_unknowns_unresolved():
    design, report = convert()
    resources = {resource.name: resource for resource in design.resources}
    assert set(resources) == {"Vpc", "Attach", "Gateway", "Subnet", "Instance", "Volume"}
    assert report.skipped == {"DevOnly": "condition IsDev is false with parameter defaults",
                              "Custom": "type outside the AWS::Service::Resource form: Custom::Lookup"}

    def value(name, prop):
        field = resources[name].field("/properties/" + prop)
        return field.selected().value if field.state == ValueState.KNOWN else field.state

    assert value("Vpc", "CidrBlock") == "10.0.0.0/16"
    assert value("Vpc", "Tags") == [{"Key": "Name", "Value": "ap-northeast-1-vpc"}]
    assert value("Subnet", "CidrBlock") == "10.0.1.0/24"
    assert value("Subnet", "MapPublicIpOnLaunch") is False
    assert resources["Subnet"].field("/properties/AssignIpv6AddressOnCreation") is None
    assert value("Instance", "ImageId") == "ami-123"
    assert value("Volume", "Size") == 20
    for name, prop in (("Subnet", "AvailabilityZone"), ("Instance", "KeyName"),
                       ("Instance", "UserData")):
        assert value(name, prop) == ValueState.UNRESOLVED
    assert report.unresolved_properties == {"Subnet": ["AvailabilityZone"],
                                            "Instance": ["KeyName", "UserData"]}


def test_template_references_become_relations_and_dependencies():
    design, _ = convert()
    by_id = {resource.id: resource for resource in design.resources}
    edges = {(by_id[r.source_resource_id].name, r.source_path, by_id[r.target_resource_id].name)
             for r in design.relations}
    assert ("Attach", "/properties/VpcId", "Vpc") in edges
    assert ("Attach", "/properties/InternetGatewayId", "Gateway") in edges
    assert ("Subnet", "/properties/VpcId", "Vpc") in edges
    templates = {resource.name: resource.template for resource in design.resources}
    assert templates["Subnet"].id == "sample.yaml"
    assert templates["Subnet"].depends_on == ["Attach"]
    # Fn::Sub on an attribute is not resolved, yet still orders the instance after the gateway.
    assert templates["Instance"].depends_on == ["Gateway"]
    assert templates["Vpc"].depends_on == []


def test_template_loader_keeps_dates_as_strings_and_rejects_transforms():
    assert load_template(TEMPLATE)["AWSTemplateFormatVersion"] == "2010-09-09"
    with pytest.raises(ValueError, match="transform"):
        convert("Transform: AWS::Serverless-2016-10-31\nResources:\n  F: {Type: AWS::Serverless::Function}\n")
    with pytest.raises(ValueError, match="Resources"):
        load_template("key: value\n")


def test_unresolved_condition_keeps_conditional_resource():
    text = TEMPLATE.replace("Env: {Type: String, Default: prod}", "Env: {Type: String}")
    lines, report = template_to_lines(load_template(text), template_id="t", **SCOPE)
    assert "DevOnly" in report.converted
    assert '"MapPublicIpOnLaunch"' not in lines and 'MapPublicIpOnLaunch={"$state": "UNRESOLVED"}' in lines


def run_lines(text):
    return run_text([TextSource(id="doc-1", name="design.txt", version="1", text=text)],
                    project="p", environment="prod", schema_dir=ROOT / "schemas",
                    profile_path=ROOT / "profiles/vpc-subnet.json", **SCOPE)[1]


def verdicts(result, rule_id):
    return [item["verdict"] for item in result["results"] if item["rule_id"] == rule_id]


def test_declarative_rules_count_properties_given_as_references():
    result = run_lines(
        "VPC main: CidrBlock=10.0.0.0/16\n"
        "AWS::EC2::InternetGateway igw: Tags=[]\n"
        "AWS::EC2::VPCGatewayAttachment attach: InternetGatewayId=@AWS::EC2::InternetGateway/igw; "
        "VpcId=@AWS::EC2::VPC/main\n")
    assert verdicts(result, "EC2.VPCGATEWAYATTACHMENT.EXACTLY_ONE_GATEWAY") == ["PASS"]
    # Both gateways given as references is still more than one.
    result = run_lines(
        "AWS::EC2::InternetGateway igw: Tags=[]\n"
        "AWS::EC2::VPNGateway vgw: Type=ipsec.1\n"
        "AWS::EC2::VPCGatewayAttachment attach: InternetGatewayId=@AWS::EC2::InternetGateway/igw; "
        "VpnGatewayId=@AWS::EC2::VPNGateway/vgw; VpcId=vpc-1\n")
    assert verdicts(result, "EC2.VPCGATEWAYATTACHMENT.EXACTLY_ONE_GATEWAY") == ["FAIL"]


def test_reference_value_needs_review_for_value_rules():
    resource = Resource(id="res-1", type="AWS::EC2::VPCGatewayAttachment", name="attach",
                        scope=Scope(environment="prod", account=SCOPE["account"], region=SCOPE["region"]))
    relation = Relation(id="rel-1", source_resource_id="res-1", source_path="/properties/VpnGatewayId",
                        unresolved_name="vgw", expected_target_type="AWS::EC2::VPNGateway",
                        evidence_ids=["ev-1"])
    view = reference_view(resource, [relation], {})
    assert view.field("/properties/VpnGatewayId").selected().value == "@AWS::EC2::VPNGateway/vgw"
    for assertion, verdict in (({"op": "present", "path": "/properties/VpnGatewayId"}, "PASS"),
                               ({"op": "absent", "path": "/properties/VpnGatewayId"}, "FAIL"),
                               ({"op": "value_in", "path": "/properties/VpnGatewayId",
                                 "values": ["vgw-1"]}, "NEEDS_REVIEW"),
                               ({"op": "matches", "path": "/properties/VpnGatewayId",
                                 "pattern": "^vgw-"}, "NEEDS_REVIEW")):
        assert _check(assertion, _Context(view))[0] == verdict, assertion
    nested = Relation(id="rel-2", source_resource_id="res-1", source_path="/properties/Ids/1",
                      unresolved_name="b", expected_target_type="AWS::EC2::Subnet")
    assert reference_view(resource, [nested], {}).field("/properties/Ids").selected().value == [
        {"$state": "UNRESOLVED"}, "@AWS::EC2::Subnet/b"]


def test_corpus_categories_and_format_deduplication():
    assert categorize({"rule_id": "R", "path": "/properties/GroupId"},
                      ["/properties/GroupId"], set()) == "reference_invisible_to_rule"
    assert categorize({"rule_id": "SCHEMA_CONSTRAINT", "path": "/properties/FromPort",
                       "reason": "'22' is not of type 'integer'", "expected": "integer",
                       "actual": "22"}, [], set()) == "string_to_scalar_coercion"
    assert categorize({"rule_id": "SCHEMA_CONSTRAINT", "path": "/properties/MinSize",
                       "reason": "2 is not of type 'string'", "expected": "string",
                       "actual": 2}, [], set()) == "scalar_to_string_coercion"
    kept, dropped = unique_templates([Path("a/x.json"), Path("a/x.yaml"), Path("b/y.json")])
    assert kept == [Path("a/x.yaml"), Path("b/y.json")] and dropped == [Path("a/x.json")]


def test_reference_uniqueness_counts_only_array_items():
    container = ('{"Name":"%s","Image":"x","LogConfiguration":{"LogDriver":"awslogs",'
                 '"Options":{"awslogs-group":"@AWS::Logs::LogGroup/logs"}}}')
    result = run_lines(
        "AWS::Logs::LogGroup logs: RetentionInDays=7\n"
        "AWS::EC2::SecurityGroup web: GroupDescription=web\n"
        f"AWS::ECS::TaskDefinition task: ContainerDefinitions=[{container % 'a'},{container % 'b'}]\n"
        'AWS::ElasticLoadBalancingV2::LoadBalancer twice: SecurityGroups=["@AWS::EC2::SecurityGroup/web","@AWS::EC2::SecurityGroup/web"]\n')
    duplicates = {item["resource_id"] for item in result["results"]
                  if item["rule_id"] == "SCHEMA_REFERENCE_UNIQUE" and item["verdict"] == "FAIL"}
    assert duplicates == {"res-4"}


def test_nested_unresolved_parts_stay_inside_known_values():
    text = TEMPLATE.replace('Tags: [{Key: Name, Value: !Sub "${AWS::Region}-vpc"}]',
                            'Tags: [{Key: Name, Value: !ImportValue shared-name}, {Key: Team, Value: web}]')
    design, report = convert(text)
    vpc = next(resource for resource in design.resources if resource.name == "Vpc")
    tags = vpc.field("/properties/Tags")
    assert tags.state == ValueState.KNOWN
    assert tags.selected().value == [{"Key": "Name", "Value": {"$state": "UNRESOLVED"}},
                                     {"Key": "Team", "Value": "web"}]
    assert report.unresolved_properties["Vpc"] == ["Tags"]
    result = run_lines('AWS::EC2::VPC v: CidrBlock=10.0.0.0/16; Tags=[{"Key":"Name","Value":{"$state":"UNRESOLVED"}}]\n')
    schema = [(item["path"], item["verdict"]) for item in result["results"]
              if item["rule_id"] in ("SCHEMA_CONSTRAINT", "SCHEMA_UNCERTAIN")]
    assert schema == [("/properties/Tags", "NEEDS_REVIEW")]


def test_unused_optional_reference_slots_need_no_review():
    result = run_lines(
        "VPC main: CidrBlock=10.0.0.0/16\n"
        "AWS::EC2::SecurityGroup web: GroupDescription=web; VpcId=@AWS::EC2::VPC/main\n"
        "AWS::EC2::SecurityGroup classic: GroupDescription=classic\n"
        "AWS::EC2::Subnet plain: VpcId=@AWS::EC2::VPC/main; CidrBlock=10.0.1.0/24\n"
        "AWS::CloudFormation::Stack child: TemplateURL=https://example.com/t.yaml\n")
    missing = {(item["resource_id"], item["path"]) for item in result["results"]
               if item["rule_id"] == "REFERENCE" and item["reason"] == "relation missing"}
    # Only the absent top-level VpcId of the second group is asked about.
    assert missing == {("res-3", "/properties/VpcId")}
