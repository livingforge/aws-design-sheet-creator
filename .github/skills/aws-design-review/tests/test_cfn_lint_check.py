"""CloudFormation export of the design and cfn-lint results mapped back to it."""
import json
from pathlib import Path

import pytest

from aws_design_sheet import cli
from aws_design_sheet.cfn_export import export_templates
from aws_design_sheet.cfn_lint_check import lint_design
from aws_design_sheet.cfn_template import import_template
from aws_design_sheet.extractor import LineExtractor, TextSource
from aws_design_sheet.runner import run_text


ROOT = Path(__file__).resolve().parents[1]
SCOPE = {"account": "111111111111", "region": "ap-northeast-1"}

NOTES = """VPC main: CidrBlock=10.0.0.0/16
AWS::EC2::Subnet app-a: CidrBlock=10.1.1.0/24; AvailabilityZone=ap-northeast-1a; VpcId=@AWS::EC2::VPC/main
AWS::Lambda::Function worker: Role=arn:aws:iam::111111111111:role/worker; Handler=index.handler; Runtime=python3.12; Timeout=1800; Code={"ZipFile": "def handler(e, c): pass"}
"""


def design_of(text):
    return LineExtractor().extract([TextSource(id="doc-1", name="design.txt", version="1", text=text)],
                                   project="p", environment="prod", **SCOPE)


def run_lines(text, **options):
    return run_text([TextSource(id="doc-1", name="design.txt", version="1", text=text)],
                    project="p", environment="prod", schema_dir=ROOT / "schemas",
                    profile_path=ROOT / "profiles/vpc-subnet.json", **SCOPE, **options)[1]


def test_export_writes_literals_refs_and_safe_logical_ids():
    [exported] = export_templates(design_of(NOTES))
    resources = exported.template["Resources"]
    assert resources["appa"]["Properties"]["VpcId"] == {"Ref": "main"}
    assert resources["appa"]["Properties"]["CidrBlock"] == "10.1.1.0/24"
    assert resources["worker"]["Properties"]["Timeout"] == 1800
    assert exported.resource_ids["appa"] == design_of(NOTES).resources[1].id
    assert "Parameters" not in exported.template


def test_unknown_values_and_other_templates_become_distinct_parameters():
    design, _ = import_template("""
Parameters: {Cidr: {Type: String}}
Resources:
  Vpc: {Type: AWS::EC2::VPC, Properties: {CidrBlock: !Ref Cidr}}
  Subnet:
    Type: AWS::EC2::Subnet
    Properties: {VpcId: !Ref Vpc, CidrBlock: !Select [0, !GetAZs ""]}
""", "t", project="p", environment="prod", **SCOPE)
    [exported] = export_templates(design)
    assert exported.template["Parameters"] == {"Unknown1": {"Type": "String"}, "Unknown2": {"Type": "String"}}
    assert exported.template["Resources"]["Vpc"]["Properties"]["CidrBlock"] == {"Ref": "Unknown1"}

    notes = ('VPC main: @Template={"id": "network", "depends_on": []}; CidrBlock=10.0.0.0/16\n'
             'AWS::EC2::Subnet app: @Template={"id": "app", "depends_on": []}; '
             'CidrBlock=10.0.1.0/24; VpcId=@AWS::EC2::VPC/main\n')
    network, app = export_templates(design_of(notes))
    assert app.template["Resources"]["app"]["Properties"]["VpcId"] == {"Ref": "Unknown1"}
    assert app.outside_relations[0]["path"] == "/properties/VpcId"


def test_lint_results_point_at_design_fields_with_evidence():
    design = design_of(NOTES)
    results, coverage = lint_design(design)
    by_rule = {r["rule_id"]: r for r in results}
    subnet = by_rule["CFN_LINT.E3059"]
    assert (subnet["verdict"], subnet["severity"], subnet["path"]) == ("FAIL", "ERROR", "/properties/CidrBlock")
    assert subnet["resource_id"] == design.resources[1].id and subnet["evidence_ids"]
    assert by_rule["CFN_LINT.E3717"]["path"] == "/properties/Timeout"
    assert "CFN_LINT.W3010" not in by_rule  # design states its AZs on purpose
    assert coverage == []


def test_matches_on_unknown_values_are_coverage_not_results():
    design, _ = import_template("""
Parameters: {Size: {Type: String}}
Resources:
  Queue: {Type: AWS::SQS::Queue, Properties: {VisibilityTimeout: !Ref Size, DelaySeconds: 1000}}
""", "t", project="p", environment="prod", **SCOPE)
    results, coverage = lint_design(design)
    assert [(r["rule_id"], r["path"]) for r in results] == [("CFN_LINT.E3034", "/properties/DelaySeconds")]
    assert {c["kind"] for c in coverage} <= {"CFN_LINT_UNKNOWN_VALUE"}


def test_checker_runs_cfn_lint_only_when_enabled():
    enabled = run_lines(NOTES, cfn_lint=True)
    assert enabled["versions"]["cfn_lint"]
    assert any(r["rule_id"] == "CFN_LINT.E3717" for r in enabled["results"])
    disabled = run_lines(NOTES)
    assert disabled["versions"]["cfn_lint"] is None
    assert not any(r["rule_id"].startswith("CFN_LINT.") for r in disabled["results"])


@pytest.mark.parametrize("flag, linted", [([], True), (["--no-cfn-lint"], False)])
def test_check_command_lints_by_default(tmp_path, flag, linted):
    source = tmp_path / "design.json"
    source.write_text(design_of(NOTES).model_dump_json(), encoding="utf-8")
    output = tmp_path / "result.json"
    assert cli.main([str(source), "--output", str(output), *flag]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert any(r["rule_id"].startswith("CFN_LINT.") for r in result["results"]) is linted


def test_schema_validation_comes_from_cfn_lint():
    result = run_lines(
        'AWS::EC2::SecurityGroupIngress quoted: GroupId=sg-0123456789abcdef0; IpProtocol=tcp; FromPort="22"; ToPort="22"; CidrIp=10.0.0.0/8\n'
        'AWS::EC2::SecurityGroupIngress invalid: GroupId=sg-0123456789abcdef0; IpProtocol=tcp; FromPort="ssh"; ToPort="22"; CidrIp=10.0.0.0/8\n'
        'AWS::Lambda::Function worker: Runtime=python3.12\n'
        'VPC main: CidrBlock=10.0.0.0/16\n'
        'AWS::EC2::Subnet app: VpcId=@AWS::EC2::VPC/main; CidrBlock=10.0.1.0/24; MapPublicIpOnLaunch="no"; '
        'Tags=[{"Key": "x"}]; Unexpected=1\n'
        'AWS::CloudFormation::Stack child: TemplateURL=https://example.com/t.yaml\n', cfn_lint=True)
    found = {(r["resource_id"], r["rule_id"], r["path"]) for r in result["results"]
             if r["rule_id"].startswith("CFN_LINT.")}
    assert found == {
        ("res-2", "CFN_LINT.E3012", "/properties/FromPort"),  # "22" converts, "ssh" does not
        ("res-3", "CFN_LINT.E3003", "/properties"),  # Code and Role are required
        ("res-5", "CFN_LINT.E3012", "/properties/MapPublicIpOnLaunch"),
        ("res-5", "CFN_LINT.E3003", "/properties/Tags/0"),
        ("res-5", "CFN_LINT.E3002", "/properties/Unexpected"),
    }  # the parent stack sets StackName, so res-6 has no finding


def test_unknown_items_do_not_hide_parent_matches():
    design, _ = import_template("""
Parameters: {Name: {Type: String}, Kms: {Type: String}}
Resources:
  Group:
    Type: AWS::ResourceGroups::Group
    Properties: {Name: g, Configuration: [{Type: !Ref Name}, {Type: a}, {Type: b}]}
  Db:
    Type: AWS::RDS::DBInstance
    Properties: {Engine: mysql, DBInstanceClass: db.t3.micro, AllocatedStorage: "20",
                 KmsKeyId: arn:aws:kms:ap-northeast-1:111111111111:key/1, MasterUserPassword: !Ref Kms}
""", "t", project="p", environment="prod", **SCOPE)
    results, coverage = lint_design(design)
    found = {(r["rule_id"], r["path"]) for r in results}
    assert ("CFN_LINT.E3032", "/properties/Configuration") in found  # three items, one unknown
    assert ("CFN_LINT.E3720", "/properties") in found  # KmsKeyId without StorageEncrypted
    assert {c["path"] for c in coverage} <= {"/properties/Configuration/0/Type", "/properties/MasterUserPassword"}
