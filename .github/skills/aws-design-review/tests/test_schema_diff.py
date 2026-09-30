import io
import json
import shutil
import zipfile
from pathlib import Path

import pytest

from aws_design_sheet.ledger import validate_ledger
from aws_design_sheet.schemas import pin


ROOT = Path(__file__).resolve().parents[1]
REMOVED = "AWS::ACMPCA::Permission"
CHANGED = "AWS::AmazonMQ::Broker"
UNTOUCHED = "AWS::XRay::Group"
ADDED = "AWS::Test::Thing"


def changed_archive() -> bytes:
    manifest = json.loads((ROOT / "schemas/manifest.json").read_text(encoding="utf-8"))
    buffer = io.BytesIO()
    with zipfile.ZipFile(ROOT / "schemas" / manifest["archive"]) as old, \
            zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as new:
        for type_name, member in manifest["types"].items():
            if type_name == REMOVED:
                continue
            schema = json.loads(old.read(member))
            if type_name == CHANGED:
                schema["properties"]["NewSetting"] = {"type": "string"}
            new.writestr(member, json.dumps(schema))
        new.writestr("aws-test-thing.json", json.dumps(
            {"typeName": ADDED, "properties": {"Name": {"type": "string"}}, "additionalProperties": False}))
    return buffer.getvalue()


@pytest.fixture()
def workspace(tmp_path):
    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    shutil.copytree(ROOT / "rules", tmp_path / "rules")
    return tmp_path


def test_schema_update_carries_the_ledger(workspace):
    result = pin(changed_archive(), "https://example.invalid/schema.zip", "ap-northeast-1",
                 workspace / "schemas", workspace / "rules")
    report = result["reconcile"]
    assert report["added"] == [ADDED]
    assert report["removed"] == [REMOVED]
    assert report["changed"] == [CHANGED]
    assert report["removed_rules"] == ["ACMPCA_PERMISSION_PRINCIPAL"]
    ledger = validate_ledger(workspace / "rules/ledger.json", workspace / "schemas")
    assert REMOVED not in ledger["types"]
    assert ledger["types"][ADDED]["state"] == "UNRESEARCHED"
    assert ledger["types"][CHANGED]["state"] == "REVIEW_REQUIRED"
    assert any("Pinned schema changed" in question for question in ledger["types"][CHANGED]["open_questions"])
    assert ledger["types"][UNTOUCHED] == json.loads(
        (ROOT / "rules/ledger.json").read_text(encoding="utf-8"))["types"][UNTOUCHED]
    ruleset = json.loads((workspace / "rules/ruleset.json").read_text(encoding="utf-8"))
    assert all(rule["source_type"] != REMOVED for rule in ruleset["rules"])


def test_reviewed_type_without_rules_returns_to_unresearched(workspace):
    ledger_path = workspace / "rules/ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger["types"][CHANGED] = {
        "service": "AmazonMQ", "state": "REVIEWED_NO_ADDITIONAL_RULES", "reviewed_at": "2026-09-29",
        "source_urls": ["https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/"
                        "aws-resource-amazonmq-broker.html"],
        "rule_ids": [], "open_questions": [], "rationale": "test"}
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    report = pin(changed_archive(), "https://example.invalid/schema.zip", "ap-northeast-1",
                 workspace / "schemas", workspace / "rules")["reconcile"]
    assert report["reset"] == [CHANGED]
    ledger = validate_ledger(ledger_path, workspace / "schemas")
    assert ledger["types"][CHANGED]["state"] == "UNRESEARCHED"


def test_unchanged_archive_is_not_reconciled(workspace):
    manifest = json.loads((ROOT / "schemas/manifest.json").read_text(encoding="utf-8"))
    archive = (ROOT / "schemas" / manifest["archive"]).read_bytes()
    before = (workspace / "rules/ledger.json").read_bytes()
    result = pin(archive, manifest["source"], "ap-northeast-1", workspace / "schemas", workspace / "rules")
    assert result["reconcile"] is None
    assert (workspace / "rules/ledger.json").read_bytes() == before
