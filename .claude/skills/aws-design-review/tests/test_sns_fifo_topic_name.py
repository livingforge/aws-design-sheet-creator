import hashlib

from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Resource, Scope, ValueState
from aws_design_sheet.checks.sns.fifo_topic_name import evaluate_sns_fifo_topic_name_suffix


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")
FIFO = "/properties/FifoTopic"
NAME = "/properties/TopicName"


def known(path, value):
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def evaluate(*fields, resource_type="AWS::SNS::Topic"):
    topic = Resource(id="topic", type=resource_type, name="topic", scope=SCOPE, fields=list(fields))
    source = "SNS design evidence"
    design = Design(project="pilot", environment="prod", account=SCOPE.account,
                    documents=[Document(id="d1", name="input", version="1", text=source,
                                        sha256=hashlib.sha256(source.encode()).hexdigest())],
                    evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1,
                                       excerpt=source)], resources=[topic])
    return evaluate_sns_fifo_topic_name_suffix(design, topic)


def test_explicit_fifo_topic_name_suffix():
    passed = evaluate(known(FIFO, True), known(NAME, "orders.fifo"))
    assert passed["rule_id"] == "SNS_FIFO_TOPIC_NAME_SUFFIX"
    assert passed["verdict"] == "PASS"
    assert passed["evidence_ids"] == ["e1"]
    failed = evaluate(known(FIFO, True), known(NAME, "orders"))
    assert failed["verdict"] == "FAIL"
    assert failed["path"] == NAME
    assert evaluate(known(FIFO, True), known(NAME, "orders.FIFO"))["verdict"] == "FAIL"


def test_fifo_topic_name_unknown_requires_review():
    result = evaluate(known(FIFO, True), FieldValue(path=NAME, state=ValueState.UNRESOLVED))
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == [NAME]
    result = evaluate(FieldValue(path=FIFO, state=ValueState.UNRESOLVED), known(NAME, "orders"))
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == [FIFO]
    assert evaluate(known(FIFO, True), known(NAME, 3))["verdict"] == "NEEDS_REVIEW"


def test_generated_name_and_standard_topic_are_outside_rule():
    assert evaluate(known(FIFO, True))["verdict"] == "NOT_APPLICABLE"
    assert evaluate(known(FIFO, False), known(NAME, "orders"))["verdict"] == "NOT_APPLICABLE"
    assert evaluate(known(NAME, "orders"))["verdict"] == "NOT_APPLICABLE"
    assert evaluate(known(FIFO, True), known(NAME, "orders"),
                    resource_type="AWS::SQS::Queue")["verdict"] == "NOT_APPLICABLE"
