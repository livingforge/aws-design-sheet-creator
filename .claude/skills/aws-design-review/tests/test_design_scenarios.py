"""End-to-end checks for the shareable design-sheet scenarios."""

from pathlib import Path

import pytest

from aws_design_sheet.excel_report import build_workbook
from aws_design_sheet.extractor import TextSource
from aws_design_sheet.runner import run_text


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "examples" / "scenarios"


def run_scenario(*names):
    sources = [TextSource(id=f"doc-{index}", name=name, version="1",
                          text=(SCENARIOS / name).read_text(encoding="utf-8"))
               for index, name in enumerate(names, 1)]
    return run_text(sources, project="scenario-demo", environment="prod",
                    account="111111111111", region="ap-northeast-1",
                    schema_dir=ROOT / "schemas",
                    profile_path=ROOT / "profiles" / "vpc-subnet.json")


@pytest.mark.parametrize("names,expected_resources", [
    (("01-network-db.txt",), 6),
    (("02-invalid-design.txt",), 5),
    (("03-conflict-a.txt", "03-conflict-b.txt"), 2),
    (("04-video-platform.txt",), 10),
    (("05-video-platform-invalid.txt",), 3),
])
def test_each_scenario_produces_a_design_sheet(names, expected_resources):
    design, result = run_scenario(*names)
    assert result["status"] == "COMPLETE"
    assert len(design.resources) == expected_resources
    workbook = build_workbook(result, design)
    assert workbook.sheetnames == ["概要", "検査結果", "未検査範囲", "設計値"]
    assert workbook["概要"]["B3"].value == "COMPLETE"
    assert workbook["設計値"].max_row > expected_resources


def test_normal_network_has_no_failures():
    design, result = run_scenario("01-network-db.txt")
    assert result["summary"].get("FAIL", 0) == 0
    assert result["summary"].get("ERROR", 0) == 0
    assert {relation.target_resource_id for relation in design.relations if relation.target_resource_id}


def test_invalid_design_finds_each_intended_error_with_source_evidence():
    design, result = run_scenario("02-invalid-design.txt")
    expected = {
        ("CIDR_CONTAINMENT", "/properties/CidrBlock"),
        ("S3_OBJECT_LOCK_CONFIGURATION_ENABLED", "/properties/ObjectLockEnabled"),
        ("SNS_FIFO_TOPIC_NAME_SUFFIX", "/properties/TopicName"),
        ("RDS_DBINSTANCE_KMS_REQUIRES_ENCRYPTION", "/properties/StorageEncrypted"),
    }
    failures = [item for item in result["results"] if item["verdict"] == "FAIL"]
    assert {(item["rule_id"], item["path"]) for item in failures} == expected
    evidence = {item.id: item for item in design.evidence}
    expected_lines = {"CIDR_CONTAINMENT": 2,
                      "S3_OBJECT_LOCK_CONFIGURATION_ENABLED": 3,
                      "SNS_FIFO_TOPIC_NAME_SUFFIX": 4,
                      "RDS_DBINSTANCE_KMS_REQUIRES_ENCRYPTION": 5}
    assert all(item["evidence_ids"] and
               expected_lines[item["rule_id"]] in
               {evidence[eid].start_line for eid in item["evidence_ids"]}
               for item in failures)


def test_conflict_is_reviewed_and_unparsed_text_is_reported():
    design, result = run_scenario("03-conflict-a.txt", "03-conflict-b.txt")
    assert not any(item["verdict"] == "FAIL" for item in result["results"])
    assert any(item["rule_id"] == "VALUE_CONFLICT" and
               item["path"] == "/properties/CidrBlock" and
               item["verdict"] == "NEEDS_REVIEW" for item in result["results"])
    assert any(item["kind"] == "UNPROCESSED_TEXT" and "doc-2: line 2" in item["reason"]
               for item in result["coverage"])
    assert len(design.resources[0].field("/properties/CidrBlock").candidates) == 2


def test_video_platform_extracts_its_workflow_without_failures():
    design, result = run_scenario("04-video-platform.txt")
    assert len(design.requirements) == 6
    assert result["summary"].get("FAIL", 0) == 0
    assert result["summary"].get("ERROR", 0) == 0
    assert {resource.type for resource in design.resources} >= {
        "AWS::S3::Bucket", "AWS::CloudFront::Distribution", "AWS::SQS::Queue",
        "AWS::DynamoDB::Table", "AWS::Lambda::Function", "AWS::ApiGatewayV2::Api"}


def test_video_platform_invalid_variant_finds_three_independent_errors():
    _, result = run_scenario("05-video-platform-invalid.txt")
    assert {(item["rule_id"], item["verdict"]) for item in result["results"]} >= {
        ("SQS_QUEUE_ENCRYPTION_OPTION_EXCLUSIVE", "FAIL"),
        ("DYNAMODB_TABLE_BILLING_THROUGHPUT", "FAIL"),
        ("SNS_FIFO_TOPIC_NAME_SUFFIX", "FAIL"),
    }
    assert result["summary"].get("FAIL") == 3
