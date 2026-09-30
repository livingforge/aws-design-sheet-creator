import hashlib

import pytest

from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Resource, Scope, ValueState
from aws_design_sheet.pilot_dynamodb import (BILLING, THROUGHPUT,
                                              evaluate_dynamodb_table_billing_throughput)


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")


def known(path, value):
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def table(*fields, type_name="AWS::DynamoDB::Table"):
    return Resource(id="table", name="table", type=type_name, scope=SCOPE, fields=list(fields))


def evaluate(resource):
    line = "design evidence"
    design = Design(project="pilot", environment="prod", account=SCOPE.account,
                    documents=[Document(id="d1", name="design", version="1", text=line,
                                        sha256=hashlib.sha256(line.encode()).hexdigest())],
                    evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1, excerpt=line)],
                    resources=[resource])
    return evaluate_dynamodb_table_billing_throughput(design, resource)


def throughput():
    return known(THROUGHPUT, {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5})


def test_provisioned_requires_throughput():
    assert evaluate(table(known(BILLING, "PROVISIONED"), throughput()))["verdict"] == "PASS"
    result = evaluate(table(known(BILLING, "PROVISIONED")))
    assert result["verdict"] == "FAIL"
    assert result["rule_id"] == "DYNAMODB_TABLE_BILLING_THROUGHPUT"
    assert result["evidence_ids"] == ["e1"]


def test_omitted_billing_uses_documented_provisioned_default():
    assert evaluate(table(throughput()))["verdict"] == "PASS"
    assert evaluate(table())["verdict"] == "FAIL"


def test_on_demand_forbids_table_provisioned_throughput():
    assert evaluate(table(known(BILLING, "PAY_PER_REQUEST")))["verdict"] == "PASS"
    assert evaluate(table(known(BILLING, "PAY_PER_REQUEST"), throughput()))["verdict"] == "FAIL"


def test_on_demand_throughput_is_outside_this_rule():
    resource = table(known(BILLING, "PAY_PER_REQUEST"),
                     known("/properties/OnDemandThroughput", {"MaxReadRequestUnits": 100}))
    assert evaluate(resource)["verdict"] == "PASS"


@pytest.mark.parametrize("state", [ValueState.INFERRED, ValueState.CONFLICT, ValueState.UNRESOLVED])
def test_unresolved_billing_needs_review(state):
    if state == ValueState.INFERRED:
        field = FieldValue(path=BILLING, state=state,
                           candidates=[Candidate(id="a", raw="PROVISIONED", value="PROVISIONED", evidence_ids=["e1"])])
    elif state == ValueState.CONFLICT:
        field = FieldValue(path=BILLING, state=state,
                           candidates=[Candidate(id="a", raw="PROVISIONED", value="PROVISIONED", evidence_ids=["e1"]),
                                       Candidate(id="b", raw="PAY_PER_REQUEST", value="PAY_PER_REQUEST", evidence_ids=["e1"])])
    else:
        field = FieldValue(path=BILLING, state=state, default_intent=True,
                           intent_evidence_ids=["e1"])
    result = evaluate(table(field, throughput()))
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == [BILLING]


def test_unresolved_throughput_needs_review():
    resource = table(known(BILLING, "PAY_PER_REQUEST"),
                     FieldValue(path=THROUGHPUT, state=ValueState.UNRESOLVED))
    result = evaluate(resource)
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == [THROUGHPUT]


def test_invalid_values_defer_to_schema_without_false_pass():
    assert evaluate(table(known(BILLING, "INVALID"), throughput()))["verdict"] == "NEEDS_REVIEW"
    assert evaluate(table(known(BILLING, "PROVISIONED"), known(THROUGHPUT, "five")))["verdict"] == "NEEDS_REVIEW"


def test_other_type_not_applicable():
    assert evaluate(table(type_name="AWS::DynamoDB::GlobalTable"))["verdict"] == "NOT_APPLICABLE"
