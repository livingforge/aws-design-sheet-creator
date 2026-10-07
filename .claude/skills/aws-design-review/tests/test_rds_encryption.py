import hashlib

import pytest

from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Relation, Resource, Scope, ValueState
from aws_design_sheet.checks.rds.encryption import ENCRYPTED, KMS, evaluate_rds_dbinstance_kms_encryption


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")


def known(path, value):
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def db(*fields, type_name="AWS::RDS::DBInstance"):
    return Resource(id="db", name="db", type=type_name, scope=SCOPE, fields=list(fields))


def design(*resources, relations=()):
    text = "design evidence"
    return Design(project="pilot", environment="prod", account=SCOPE.account,
                  documents=[Document(id="doc", name="source", version="1", text=text,
                                      sha256=hashlib.sha256(text.encode()).hexdigest())],
                  evidence=[Evidence(id="e1", document_id="doc", start_line=1, end_line=1, excerpt=text)],
                  resources=list(resources), relations=list(relations))


def evaluate(resource, *others, relations=()):
    return evaluate_rds_dbinstance_kms_encryption(design(resource, *others, relations=relations), resource)


def test_ordinary_create_known_key_and_encryption():
    resource = db(known(KMS, "arn:aws:kms:ap-northeast-1:111111111111:key/example"),
                  known(ENCRYPTED, True))
    result = evaluate(resource)
    assert result["verdict"] == "PASS"
    assert result["rule_id"] == "RDS_DBINSTANCE_KMS_REQUIRES_ENCRYPTION"
    assert result["evidence_ids"] == ["e1"]


@pytest.mark.parametrize("value", [False, None])
def test_key_without_enabled_encryption_fails(value):
    fields = [known(KMS, "key-1")]
    if value is not None:
        fields.append(known(ENCRYPTED, value))
    assert evaluate(db(*fields))["verdict"] == "FAIL"


def test_no_key_is_not_applicable_even_if_encrypted():
    assert evaluate(db(known(ENCRYPTED, True)))["verdict"] == "NOT_APPLICABLE"


@pytest.mark.parametrize("path", [
    "/properties/DBClusterIdentifier", "/properties/DBSnapshotIdentifier",
    "/properties/SourceDBInstanceIdentifier", "/properties/SourceDbiResourceId",
    "/properties/SourceDBInstanceAutomatedBackupsArn",
])
def test_restore_replica_and_cluster_cases_are_out_of_scope(path):
    resource = db(known(KMS, "key-1"), known(ENCRYPTED, False), known(path, "source"))
    assert evaluate(resource)["verdict"] == "NOT_APPLICABLE"


def test_aurora_engine_is_out_of_scope():
    resource = db(known(KMS, "key-1"), known("/properties/Engine", "aurora-postgresql"))
    assert evaluate(resource)["verdict"] == "NOT_APPLICABLE"


def test_definite_exception_takes_precedence_over_uncertain_key():
    resource = db(FieldValue(path=KMS, state=ValueState.UNRESOLVED),
                  known("/properties/DBSnapshotIdentifier", "snapshot"))
    assert evaluate(resource)["verdict"] == "NOT_APPLICABLE"


def test_uncertain_exception_condition_prevents_false_failure():
    path = "/properties/DBSnapshotIdentifier"
    resource = db(known(KMS, "key-1"),
                  FieldValue(path=path, state=ValueState.UNRESOLVED))
    result = evaluate(resource)
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == [path]


@pytest.mark.parametrize("state", [ValueState.CONFLICT, ValueState.UNRESOLVED])
def test_uncertain_encryption_needs_review(state):
    if state == ValueState.CONFLICT:
        field = FieldValue(path=ENCRYPTED, state=state,
                           candidates=[Candidate(id="a", raw="true", value=True, evidence_ids=["e1"]),
                                       Candidate(id="b", raw="false", value=False, evidence_ids=["e1"])])
    else:
        field = FieldValue(path=ENCRYPTED, state=state)
    result = evaluate(db(known(KMS, "key-1"), field))
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == [ENCRYPTED]


def test_uncertain_or_invalid_key_needs_review():
    resource = db(FieldValue(path=KMS, state=ValueState.UNRESOLVED), known(ENCRYPTED, True))
    assert evaluate(resource)["verdict"] == "NEEDS_REVIEW"
    resource.fields[0] = known(KMS, "")
    assert evaluate(resource)["verdict"] == "NEEDS_REVIEW"


def test_logical_kms_reference_and_wrong_type():
    resource = db(known(ENCRYPTED, True))
    key = Resource(id="key", name="key", type="AWS::KMS::Key", scope=SCOPE)
    ref = Relation(id="r1", source_resource_id="db", source_path=KMS,
                   target_resource_id="key", expected_target_type="AWS::KMS::Key", evidence_ids=["e1"])
    assert evaluate(resource, key, relations=[ref])["verdict"] == "PASS"
    ref.expected_target_type = "AWS::IAM::Role"
    assert evaluate(resource, key, relations=[ref])["verdict"] == "FAIL"
    ref.expected_target_type = "AWS::KMS::Key"
    ref.target_resource_id = None
    assert evaluate(resource, key, relations=[ref])["verdict"] == "NEEDS_REVIEW"


def test_other_resource_type_not_applicable():
    assert evaluate(db(type_name="AWS::RDS::DBSubnetGroup"))["verdict"] == "NOT_APPLICABLE"
