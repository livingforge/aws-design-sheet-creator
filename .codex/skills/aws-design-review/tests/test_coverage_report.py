import json
from pathlib import Path

import pytest

from aws_design_sheet.coverage_report import build_report, main


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "rules/ledger.json"
SCHEMAS = ROOT / "schemas"


def test_baseline_report_reconciles_all_types():
    report = build_report(LEDGER, SCHEMAS)
    assert report["total_types"] == 1606
    assert sum(report["state_counts"].values()) == 1606
    assert sum(row["total"] for row in report["namespace_counts"].values()) == 1606
    assert report["namespace_counts"]["EC2"]["total"] == 117
    assert len(report["unresearched_types"]) == report["state_counts"]["UNRESEARCHED"]
    assert sum(row["total"] for row in report["tier_counts"].values()) == 1606
    assert sum(row["rule_count"] for row in report["tier_counts"].values()) == report["rule_count"]
    assert sum(row["open_question_count"] for row in report["tier_counts"].values()) == report["open_question_count"]
    assert report["tier_counts"]["T1"]["rule_count"] == sum(
        report["namespace_counts"][namespace]["rule_count"]
        for namespace in report["tier_counts"]["T1"]["namespaces"])
    assert report["tier_counts"]["T1"]["state_counts"]["REVIEW_REQUIRED"] == sum(
        report["namespace_counts"][namespace]["state_counts"]["REVIEW_REQUIRED"]
        for namespace in report["tier_counts"]["T1"]["namespaces"])
    assert set(report["tier_counts"]["T1"]["namespaces"]) == {"EC2", "IAM", "Lambda", "RDS", "S3"}


def test_reviewed_type_changes_counts_and_cli_writes_file(tmp_path):
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    baseline = build_report(LEDGER, SCHEMAS)
    before = baseline["state_counts"]["REVIEWED_NO_ADDITIONAL_RULES"]
    before_s3 = baseline["namespace_counts"]["S3"]["state_counts"]["REVIEWED_NO_ADDITIONAL_RULES"]
    ledger["types"]["AWS::S3::Bucket"].update(
        state="REVIEWED_NO_ADDITIONAL_RULES", reviewed_at="2026-09-29",
        source_urls=["https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-bucket.html"],
        rationale="Reviewed in test", rule_ids=[], open_questions=[])
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    output = tmp_path / "nested/report.json"
    assert main(["--ledger", str(ledger_path), "--schemas", str(SCHEMAS),
                 "--output", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["state_counts"]["REVIEWED_NO_ADDITIONAL_RULES"] == before + 1
    assert report["namespace_counts"]["S3"]["state_counts"]["REVIEWED_NO_ADDITIONAL_RULES"] == before_s3 + 1
    assert "AWS::S3::Bucket" not in report["unresearched_types"]


def test_invalid_ledger_fails_without_coverage_claim(tmp_path):
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    ledger["types"].pop("AWS::S3::Bucket")
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(ledger), encoding="utf-8")
    output = tmp_path / "report.json"
    assert main(["--ledger", str(path), "--schemas", str(SCHEMAS),
                 "--output", str(output)]) == 2
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "FAILED"
    assert "state_counts" not in report


def test_custom_tiers_can_replace_the_provisional_priority(tmp_path):
    tiers = {"tier_version": "project-1", "tiers": {"T1": ["S3"]},
             "default_tier": "T3"}
    path = tmp_path / "tiers.json"
    path.write_text(json.dumps(tiers), encoding="utf-8")
    report = build_report(LEDGER, SCHEMAS, path)
    assert report["tier_version"] == "project-1"
    assert report["tier_counts"]["T1"]["namespaces"] == ["S3"]
    assert report["tier_counts"]["T1"]["total"] == report["namespace_counts"]["S3"]["total"]
    tiers["tiers"]["T2"] = ["S3"]
    path.write_text(json.dumps(tiers), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate tier namespace"):
        build_report(LEDGER, SCHEMAS, path)
