import hashlib

from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Resource, Scope, ValueState
from aws_design_sheet.checks.s3.object_lock import evaluate_s3_object_lock_configuration_enabled


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")
CONFIG = "/properties/ObjectLockConfiguration"
ENABLED = "/properties/ObjectLockEnabled"


def known(path, value):
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def evaluate(*fields, type_name="AWS::S3::Bucket"):
    bucket = Resource(id="bucket", type=type_name, name="bucket", scope=SCOPE, fields=list(fields))
    source = "S3 Object Lock evidence"
    design = Design(project="pilot", environment="prod", account=SCOPE.account,
                    documents=[Document(id="d1", name="input", version="1", text=source,
                                        sha256=hashlib.sha256(source.encode()).hexdigest())],
                    evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                       excerpt=source)], resources=[bucket])
    return evaluate_s3_object_lock_configuration_enabled(design, bucket)


def test_object_lock_requires_bucket_level_true():
    config = known(CONFIG, {"ObjectLockEnabled": "Enabled"})
    passed = evaluate(config, known(ENABLED, True))
    assert passed["verdict"] == "PASS"
    assert passed["rule_id"] == "S3_OBJECT_LOCK_CONFIGURATION_ENABLED"
    assert passed["evidence_ids"] == ["e1"]
    assert evaluate(config, known(ENABLED, False))["verdict"] == "FAIL"
    assert evaluate(config)["verdict"] == "FAIL"


def test_inner_object_lock_enabled_does_not_substitute_for_top_level():
    result = evaluate(known(CONFIG, {"ObjectLockEnabled": "Enabled"}))
    assert result["verdict"] == "FAIL"
    assert result["path"] == ENABLED


def test_object_lock_unknown_values_need_review():
    unresolved = FieldValue(path=CONFIG, state=ValueState.UNRESOLVED)
    result = evaluate(unresolved, known(ENABLED, True))
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == [CONFIG]
    result = evaluate(known(CONFIG, {}), FieldValue(path=ENABLED, state=ValueState.CONFLICT,
                        candidates=[Candidate(id="yes", raw="true", value=True, evidence_ids=["e1"]),
                                    Candidate(id="no", raw="false", value=False, evidence_ids=["e1"])]))
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == [ENABLED]
    assert evaluate(known(CONFIG, {}), known(ENABLED, "true"))["verdict"] == "NEEDS_REVIEW"


def test_object_lock_non_applicable():
    assert evaluate()["verdict"] == "NOT_APPLICABLE"
    assert evaluate(FieldValue(path=CONFIG, state=ValueState.NOT_APPLICABLE))["verdict"] == "NOT_APPLICABLE"
    assert evaluate(known(CONFIG, {}), known(ENABLED, False), type_name="AWS::IAM::Policy")["verdict"] == "NOT_APPLICABLE"
