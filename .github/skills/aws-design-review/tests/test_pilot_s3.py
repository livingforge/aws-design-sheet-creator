import hashlib

import pytest

from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Relation, Resource, Scope, ValueState
from aws_design_sheet.pilot_s3 import (REPLICATION, STATUS, VERSIONING,
                                       evaluate_s3_replication_versioning)


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")
DEST_PATH = REPLICATION + "/Rules/0/Destination/Bucket"


def known(path, value):
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def bucket(id, *fields, scope=SCOPE, type_name="AWS::S3::Bucket"):
    return Resource(id=id, name=id, type=type_name, scope=scope, fields=list(fields))


def design(*resources, relations=()):
    line = "source line"
    return Design(project="pilot", environment="prod", account=SCOPE.account,
                  documents=[Document(id="d1", name="design", version="1", text=line,
                                      sha256=hashlib.sha256(line.encode()).hexdigest())],
                  evidence=[Evidence(id="e1", document_id="d1", start_line=1,
                                     end_line=1, excerpt=line)],
                  resources=list(resources), relations=list(relations))


def replication(destination="@AWS::S3::Bucket/dest"):
    return known(REPLICATION, {"Role": "arn:aws:iam::111111111111:role/repl", "Rules": [
        {"Destination": {"Bucket": destination}, "Status": "Enabled"}]})


def relation(*, target_id="dest", expected="AWS::S3::Bucket", name=None):
    return Relation(id="r1", source_resource_id="source", source_path=DEST_PATH,
                    target_resource_id=target_id, unresolved_name=name,
                    expected_target_type=expected, evidence_ids=["e1"])


def evaluate(source, destination=None, refs=()):
    resources = [source] + ([destination] if destination is not None else [])
    return evaluate_s3_replication_versioning(design(*resources, relations=refs), source)


def test_enabled_source_and_destination_pass():
    source = bucket("source", replication(), known(VERSIONING, {"Status": "Enabled"}))
    destination = bucket("dest", known(STATUS, "Enabled"))
    result = evaluate(source, destination, [relation()])
    assert result["verdict"] == "PASS"
    assert result["rule_id"] == "S3_REPLICATION_VERSIONING"
    assert result["evidence_ids"] == ["e1"]


@pytest.mark.parametrize("fields", [(), (known(VERSIONING, {}),), (known(STATUS, "Suspended"),)])
def test_source_missing_or_suspended_fails(fields):
    source = bucket("source", replication(), *fields)
    destination = bucket("dest", known(STATUS, "Enabled"))
    assert evaluate(source, destination, [relation()])["verdict"] == "FAIL"


def test_destination_suspended_fails_and_unknown_needs_review():
    source = bucket("source", replication(), known(STATUS, "Enabled"))
    destination = bucket("dest", known(STATUS, "Suspended"))
    assert evaluate(source, destination, [relation()])["verdict"] == "FAIL"
    destination.fields = [FieldValue(path=STATUS, state=ValueState.CONFLICT,
                                     candidates=[Candidate(id="a", raw="Enabled", value="Enabled", evidence_ids=["e1"]),
                                                 Candidate(id="b", raw="Suspended", value="Suspended", evidence_ids=["e1"])])]
    result = evaluate(source, destination, [relation()])
    assert result["verdict"] == "NEEDS_REVIEW"
    assert "dest:" + STATUS in result["dependencies"]


def test_external_arn_and_unresolved_reference_need_review():
    source = bucket("source", replication("arn:aws:s3:::external"), known(STATUS, "Enabled"))
    assert evaluate(source)["verdict"] == "NEEDS_REVIEW"
    result = evaluate(source, refs=[relation(target_id=None, name="missing")])
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == [DEST_PATH]


def test_relation_does_not_override_conflicting_literal():
    source = bucket("source", replication("arn:aws:s3:::external"), known(STATUS, "Enabled"))
    destination = bucket("dest", known(STATUS, "Enabled"))
    assert evaluate(source, destination, [relation()])["verdict"] == "NEEDS_REVIEW"
    source.fields[0] = replication("@AWS::S3::Bucket/other")
    assert evaluate(source, destination, [relation()])["verdict"] == "NEEDS_REVIEW"


def test_wrong_reference_type_and_target_type_fail():
    source = bucket("source", replication(), known(STATUS, "Enabled"))
    destination = bucket("dest", known(STATUS, "Enabled"))
    assert evaluate(source, destination, [relation(expected="AWS::IAM::Role")])["verdict"] == "FAIL"
    wrong = bucket("dest", type_name="AWS::IAM::Role")
    assert evaluate(source, wrong, [relation()])["verdict"] == "FAIL"


def test_explicit_cross_region_target_is_allowed_but_name_lookup_is_scoped():
    source = bucket("source", replication(), known(STATUS, "Enabled"))
    other = Scope(environment="prod", account="222222222222", region="us-west-2")
    destination = bucket("dest", known(STATUS, "Enabled"), scope=other)
    assert evaluate(source, destination, [relation()])["verdict"] == "PASS"
    assert evaluate(source, destination, [relation(target_id=None, name="dest")])["verdict"] == "NEEDS_REVIEW"


def test_no_replication_not_applicable_and_uncertain_replication_review():
    source = bucket("source", known(STATUS, "Enabled"))
    assert evaluate(source)["verdict"] == "NOT_APPLICABLE"
    source.fields.append(FieldValue(path=REPLICATION, state=ValueState.UNRESOLVED))
    result = evaluate(source)
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == [REPLICATION]


def test_missing_destination_rules_prevents_vacuous_pass():
    source = bucket("source", known(REPLICATION, {"Rules": []}), known(STATUS, "Enabled"))
    assert evaluate(source)["verdict"] == "NEEDS_REVIEW"


def test_other_type_not_applicable():
    source = bucket("source", type_name="AWS::IAM::Role")
    assert evaluate(source)["verdict"] == "NOT_APPLICABLE"
