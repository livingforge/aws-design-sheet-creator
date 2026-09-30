"""Bare names become relations only for catalogued properties and exact name matches."""
from pathlib import Path

from aws_design_sheet.checker import REFERENCE_TYPES, Checker
from aws_design_sheet.extractor import LineExtractor, TextSource
from aws_design_sheet.runner import run_text


ROOT = Path(__file__).resolve().parents[1]
CATALOG = {**REFERENCE_TYPES, ("AWS::EC2::RouteTable", "/properties/VpcId"): "AWS::EC2::VPC",
           ("AWS::Test::Group", "/properties/SubnetIds/*"): "AWS::EC2::Subnet"}


def extract(text, catalog=CATALOG):
    return LineExtractor(catalog).extract([TextSource(id="doc-1", name="d.txt", version="1", text=text)],
                                          project="p", environment="prod", account="111111111111",
                                          region="ap-northeast-1")


def test_exact_name_becomes_relation():
    design = extract("VPC main: CidrBlock=10.0.0.0/16\n"
                     "AWS::EC2::RouteTable rt: VpcId=main")
    table = design.resources[1]
    assert design.extractor_version == "line-v4"
    assert table.field("/properties/VpcId") is None
    [relation] = design.relations
    assert (relation.source_path, relation.target_resource_id, relation.expected_target_type) == (
        "/properties/VpcId", design.resources[0].id, "AWS::EC2::VPC")
    assert relation.evidence_ids


def test_physical_ids_and_partial_arrays_stay_literal():
    design = extract("VPC main: CidrBlock=10.0.0.0/16\n"
                     "AWS::EC2::RouteTable rt: VpcId=vpc-0123456789abcdef0\n"
                     "Subnet a: Vpc=main; CidrBlock=10.0.1.0/24\n"
                     'AWS::Test::Group g: SubnetIds=["a","subnet-0abc"]')
    assert design.resources[1].field("/properties/VpcId").selected().value == "vpc-0123456789abcdef0"
    assert design.resources[3].field("/properties/SubnetIds").selected().value == ["a", "subnet-0abc"]
    both = extract("VPC main: CidrBlock=10.0.0.0/16\n"
                   "Subnet a: Vpc=main; CidrBlock=10.0.1.0/24\n"
                   "Subnet b: Vpc=main; CidrBlock=10.0.2.0/24\n"
                   'AWS::Test::Group g: SubnetIds=["a","b"]')
    paths = [r.source_path for r in both.relations if r.source_resource_id == both.resources[3].id]
    assert paths == ["/properties/SubnetIds/0", "/properties/SubnetIds/1"]


def test_without_catalog_behaviour_is_unchanged():
    design = LineExtractor().extract([TextSource(id="doc-1", name="d.txt", version="1",
                                                 text="VPC main: CidrBlock=10.0.0.0/16\n"
                                                      "AWS::EC2::RouteTable rt: VpcId=main")],
                                     project="p", environment="prod", account="111111111111",
                                     region="ap-northeast-1")
    assert design.extractor_version == "line-v3"
    assert design.resources[1].field("/properties/VpcId").selected().value == "main"
    assert design.relations == []


def test_runner_links_names_for_built_in_references():
    text = ("VPC main: CidrBlock=10.0.0.0/16\n"
            "AWS::EC2::Subnet app: VpcId=main; CidrBlock=10.0.1.0/24")
    design, result = run_text([TextSource(id="doc-1", name="d.txt", version="1", text=text)],
                              project="p", environment="prod", account="111111111111",
                              region="ap-northeast-1", schema_dir=ROOT / "schemas",
                              profile_path=ROOT / "profiles/vpc-subnet.json")
    assert [r.source_path for r in design.relations] == ["/properties/VpcId"]
    assert any(r["rule_id"] == "CIDR_CONTAINMENT" and r["verdict"] == "PASS" for r in result["results"])
    assert Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").reference_types[
        ("AWS::EC2::Subnet", "/properties/VpcId")] == "AWS::EC2::VPC"
