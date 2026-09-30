from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.extractor import LineExtractor, TextSource

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
