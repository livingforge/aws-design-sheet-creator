"""Namespace review fragments: offline validation and merge into the rule files."""
import copy
import json
import shutil
from pathlib import Path

import pytest

from aws_design_sheet.ledger import validate_ledger
from aws_design_sheet.rule_review import (PinnedSchemas, dump_json, merge_fragments,
                                          review_material, validate_fragment)


ROOT = Path(__file__).resolve().parents[1]
TYPE = "AWS::ApplicationInsights::Application"
PAGE = "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-applicationinsights-application.html"
RULE = {
    "id": "APPLICATIONINSIGHTS.APPLICATION.TEST_OPS_TOPIC",
    "version": "1.0.0", "source_type": TYPE, "authority": "AWS_SPEC", "severity": "WARNING",
    "description": "Test rule: an OpsItem topic is given only when OpsCenter is enabled.",
    "when": {"op": "field_equals", "path": "/properties/OpsCenterEnabled", "equals": False},
    "assert": {"op": "absent", "path": "/properties/OpsItemSNSTopicArn"},
    "source_urls": [PAGE], "source_checked_at": "2026-09-29",
    "basis": [{"pointer": "/properties/OpsCenterEnabled",
               "quote": "When set to true, creates opsItems for any problems detected on an application."}],
    "examples": [
        {"fields": {"/properties/OpsCenterEnabled": False}, "verdict": "PASS"},
        {"fields": {"/properties/OpsCenterEnabled": False,
                    "/properties/OpsItemSNSTopicArn": "arn:aws:sns:ap-northeast-1:111111111111:t"},
         "verdict": "FAIL"},
        {"fields": {"/properties/OpsCenterEnabled": {"$state": "UNRESOLVED"}}, "verdict": "NEEDS_REVIEW"},
        {"fields": {"/properties/OpsCenterEnabled": True}, "verdict": "NOT_APPLICABLE"}]}
FRAGMENT = {
    "fragment_version": "1.0.0", "namespace": "ApplicationInsights", "reviewed_at": "2026-09-29",
    "types": {TYPE: {"state": "RULES_REGISTERED", "source_urls": [PAGE],
                     "rule_ids": [RULE["id"]], "open_questions": []}},
    "rules": [RULE],
    "references": [{"source_type": TYPE, "path": "/properties/OpsItemSNSTopicArn",
                    "target_type": "AWS::SNS::Topic",
                    "basis": [{"pointer": "/properties/OpsItemSNSTopicArn",
                               "quote": "The SNS topic provided to Application Insights"}]}]}


@pytest.fixture(scope="module")
def context():
    schemas = PinnedSchemas(ROOT / "schemas")
    ledger = json.loads((ROOT / "rules/ledger.json").read_text(encoding="utf-8"))
    ruleset = json.loads((ROOT / "rules/ruleset.json").read_text(encoding="utf-8"))
    references = {"catalog_version": "0", "references": []}
    if ledger["types"][TYPE]["state"] != "UNRESEARCHED":
        ledger["types"][TYPE] = {"service": "ApplicationInsights", "state": "UNRESEARCHED",
                                 "source_urls": [], "rule_ids": [], "open_questions": []}
    ruleset["rules"] = [rule for rule in ruleset["rules"] if rule["source_type"] != TYPE]
    return schemas, ledger, ruleset, references


def errors(fragment, context):
    return validate_fragment(fragment, *context)


def test_valid_fragment(context):
    assert errors(FRAGMENT, context) == []


@pytest.mark.parametrize("change,message", [
    (lambda f: f["rules"][0]["basis"][0].update(quote="Always creates opsItems."), "basis quote not found"),
    (lambda f: f["rules"][0]["basis"][0].update(pointer="/properties/Missing"), "not in pinned schema"),
    (lambda f: f["rules"][0]["examples"][1].update(verdict="PASS"), "expected PASS"),
    (lambda f: f["rules"][0]["examples"].pop(), "examples lack verdicts"),
    (lambda f: f["rules"][0].update(id="OTHER.TEST"), "rule id must start with"),
    (lambda f: f["rules"][0].update(authority="PROJECT_POLICY"), "AWS_SPEC rules only"),
    (lambda f: f["types"].clear(), "unresearched type missing"),
    (lambda f: f["types"][TYPE].update(rule_ids=[]), "rule_ids must list exactly"),
    (lambda f: f["types"][TYPE].update(state="REVIEWED_NO_ADDITIONAL_RULES"), "no-additional-rules"),
    (lambda f: f["types"][TYPE].update(source_urls=["https://example.com/"]), "AWS HTTPS"),
    (lambda f: f["references"][0].update(target_type="AWS::Nope::Nope"), "absent from pinned schema"),
    (lambda f: f["references"][0]["basis"][0].update(quote="nope"), "basis quote not found"),
    (lambda f: f["rules"][0].update(basis=[{"url": "https://example.com/page", "quote": "q"}]),
     "Template Reference page"),
])
def test_fragment_problems_are_reported(context, change, message):
    fragment = copy.deepcopy(FRAGMENT)
    change(fragment)
    found = errors(fragment, context)
    assert any(message in item for item in found), found


def test_merge_updates_ledger_ruleset_and_references(tmp_path, context):
    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    (tmp_path / "rules").mkdir()
    _, ledger, ruleset, _ = context
    (tmp_path / "rules/ledger.json").write_text(dump_json(ledger), encoding="utf-8")
    (tmp_path / "rules/ruleset.json").write_text(dump_json(ruleset), encoding="utf-8")
    fragment = tmp_path / "fragment.json"
    fragment.write_text(json.dumps(FRAGMENT), encoding="utf-8")
    result = merge_fragments([fragment], tmp_path)
    assert result == {"merged": ["ApplicationInsights"], "types": 1, "rules": 1, "references": 1}
    merged = validate_ledger(tmp_path / "rules/ledger.json", tmp_path / "schemas")
    assert merged["types"][TYPE]["state"] == "RULES_REGISTERED"
    assert merged["types"][TYPE]["reviewed_at"] == "2026-09-29"
    references = json.loads((tmp_path / "rules/references.json").read_text(encoding="utf-8"))
    assert references["references"][0]["target_type"] == "AWS::SNS::Topic"
    with pytest.raises(ValueError, match="already reviewed"):
        merge_fragments([fragment], tmp_path)


def test_material_lists_schema_descriptions():
    text = review_material("ApplicationInsights", ROOT)
    assert f"## {TYPE}" in text
    assert "- /properties/OpsCenterEnabled: When set to true" in text
