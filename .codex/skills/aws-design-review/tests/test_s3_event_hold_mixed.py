import hashlib
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import (Candidate, Design, Document, Evidence, FieldValue,
                                     Resource, Scope, ValueState)
from aws_design_sheet.checks.s3.event_hold_mixed import evaluate_s3_event_hold_mixed_units as evaluate


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")


def configuration(retention, hold):
    return {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {
        "Mode": "GOVERNANCE", **retention, "DefaultEventHold": hold}}}


def case(config, state=ValueState.KNOWN):
    path = "/properties/ObjectLockConfiguration"
    fields = ([FieldValue(path=path, state=ValueState.KNOWN,
                          candidates=[Candidate(id="cfg", raw="config", value=config, evidence_ids=["e1"])],
                          selected_candidate_id="cfg")]
              if state == ValueState.KNOWN else [FieldValue(path=path, state=state)])
    bucket = Resource(id="bucket", type="AWS::S3::Bucket", name="bucket", scope=SCOPE, fields=fields)
    text = "S3 event hold design"
    design = Design(project="pilot", environment="prod", account=SCOPE.account,
                    documents=[Document(id="d1", name="input", version="1", text=text,
                                        sha256=hashlib.sha256(text.encode()).hexdigest())],
                    evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                       excerpt=text)], resources=[bucket])
    return design, bucket


def test_mixed_units_definite_failure_and_pass():
    design, bucket = case(configuration({"Days": 364}, {"Years": 1}))
    assert evaluate(design, bucket)["verdict"] == "FAIL"
    design, bucket = case(configuration({"Days": 367}, {"Years": 1}))
    assert evaluate(design, bucket)["verdict"] == "PASS"
    design, bucket = case(configuration({"Years": 1}, {"Days": 367}))
    assert evaluate(design, bucket)["verdict"] == "FAIL"
    design, bucket = case(configuration({"Years": 1}, {"Days": 364}))
    assert evaluate(design, bucket)["verdict"] == "PASS"


def test_mixed_units_boundary_requires_review():
    design, bucket = case(configuration({"Days": 365}, {"Years": 1}))
    assert evaluate(design, bucket)["verdict"] == "NEEDS_REVIEW"
    design, bucket = case(configuration({"Years": 1}, {"Days": 366}))
    assert evaluate(design, bucket)["verdict"] == "NEEDS_REVIEW"


def test_same_unit_and_missing_hold_are_covered_elsewhere():
    design, bucket = case(configuration({"Days": 30}, {"Days": 10}))
    assert evaluate(design, bucket)["verdict"] == "NOT_APPLICABLE"
    design, bucket = case({"ObjectLockEnabled": "Enabled"})
    assert evaluate(design, bucket)["verdict"] == "NOT_APPLICABLE"


def test_unresolved_config_requires_review():
    design, bucket = case(None, ValueState.UNRESOLVED)
    assert evaluate(design, bucket)["verdict"] == "NEEDS_REVIEW"


def test_checker_includes_mixed_unit_finding():
    design, _ = case(configuration({"Days": 364}, {"Years": 1}))
    root = Path(__file__).resolve().parents[1]
    report = Checker(root / "schemas", root / "profiles/vpc-subnet.json").check(design)
    findings = [row for row in report["results"]
                if row["rule_id"] == "S3_EVENT_HOLD_WITHIN_RETENTION_MIXED_UNITS"]
    assert len(findings) == 1
    assert findings[0]["verdict"] == "FAIL"
