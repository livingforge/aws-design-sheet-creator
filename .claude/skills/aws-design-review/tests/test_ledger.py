import json
from pathlib import Path

import pytest

from aws_design_sheet.ledger import validate_ledger


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "rules/ledger.json"
SCHEMAS = ROOT / "schemas"
TYPE = "AWS::SQS::QueuePolicy"
SOURCE = "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sqs-queuepolicy.html"


def edited(tmp_path, change):
    data = json.loads(LEDGER.read_text(encoding="utf-8"))
    data["types"][TYPE] = {"service": "SQS", "state": "UNRESEARCHED", "source_urls": [],
                           "rule_ids": [], "open_questions": []}
    change(data)
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_pinned_ledger_tracks_every_type_and_partial_reviews():
    data = validate_ledger(LEDGER, SCHEMAS)
    assert len(data["types"]) == 1606
    counts = {state: sum(entry["state"] == state for entry in data["types"].values())
              for state in ("UNRESEARCHED", "REVIEWED_NO_ADDITIONAL_RULES", "RULES_REGISTERED",
                            "REVIEW_REQUIRED")}
    assert sum(counts.values()) == 1606
    assert counts["REVIEW_REQUIRED"] >= 35
    for entry in data["types"].values():
        if entry["state"] != "UNRESEARCHED":
            assert entry["reviewed_at"] and entry["source_urls"]


def test_type_set_and_zip_hash_are_pinned(tmp_path):
    with pytest.raises(ValueError, match="type set mismatch"):
        validate_ledger(edited(tmp_path, lambda d: d["types"].pop("AWS::S3::Bucket")), SCHEMAS)
    with pytest.raises(ValueError, match="ZIP hash mismatch"):
        validate_ledger(edited(tmp_path, lambda d: d.update(schema_zip_sha256="0" * 64)), SCHEMAS)


def test_review_requires_date_source_and_rationale(tmp_path):
    def change(data):
        data["types"][TYPE].update(state="REVIEWED_NO_ADDITIONAL_RULES")
    with pytest.raises(ValueError, match="reviewed_at"):
        validate_ledger(edited(tmp_path, change), SCHEMAS)

    def complete(data):
        change(data)
        data["types"][TYPE].update(
            reviewed_at="2026-09-29", source_urls=[SOURCE], rationale="No additional rule found")
    validate_ledger(edited(tmp_path, complete), SCHEMAS)

    def questionable(data):
        complete(data)
        data["types"][TYPE]["source_urls"] = ["https://example.com/"]
    with pytest.raises(ValueError, match="AWS HTTPS sources"):
        validate_ledger(edited(tmp_path, questionable), SCHEMAS)


def test_registered_rule_must_exist_for_same_type(tmp_path):
    def change(data):
        data["types"][TYPE].update(
            state="RULES_REGISTERED", reviewed_at="2026-09-29",
            source_urls=[SOURCE], rule_ids=["AWS.S3.BUCKET.EXAMPLE"])
    path = edited(tmp_path, change)
    with pytest.raises(ValueError, match="rule ID missing"):
        validate_ledger(path, SCHEMAS)
    ruleset = tmp_path / "ruleset.json"
    baseline = json.loads((ROOT / "rules/ruleset.json").read_text(encoding="utf-8"))["rules"]
    ruleset.write_text(json.dumps({"rules": [*baseline, {"id": "AWS.S3.BUCKET.EXAMPLE",
                                                "source_type": TYPE}]}), encoding="utf-8")
    validate_ledger(path, SCHEMAS, ruleset)
    ruleset.write_text(json.dumps({"rules": [*baseline, {"id": "AWS.S3.BUCKET.EXAMPLE",
                                                "source_type": "AWS::S3::BucketPolicy"}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="source type differs"):
        validate_ledger(path, SCHEMAS, ruleset)


def test_review_required_has_explicit_question(tmp_path):
    def change(data):
        data["types"][TYPE].update(state="REVIEW_REQUIRED", reviewed_at="2026-09-29",
                                                   source_urls=[SOURCE])
    with pytest.raises(ValueError, match="open questions"):
        validate_ledger(edited(tmp_path, change), SCHEMAS)


def test_duplicate_ruleset_ids_are_rejected(tmp_path):
    ruleset = tmp_path / "ruleset.json"
    rule = {"id": "DUPLICATE", "source_type": "AWS::S3::Bucket"}
    ruleset.write_text(json.dumps({"rules": [rule, rule]}), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate ruleset rule ID"):
        validate_ledger(LEDGER, SCHEMAS, ruleset)
