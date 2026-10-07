"""Lambda event source mapping source-specific checks."""
import pytest

from aws_design_sheet.models import Candidate, FieldValue, Resource, Scope, ValueState
from aws_design_sheet.checks.lambda_.event_source import evaluate_lambda_event_source, evaluate_lambda_source_property_scope


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")
KINESIS = "arn:aws:kinesis:ap-northeast-1:111111111111:stream/orders"
DYNAMODB = "arn:aws:dynamodb:ap-northeast-1:111111111111:table/orders/stream/2026-01-01T00:00:00.000"
SQS = "arn:aws:sqs:ap-northeast-1:111111111111:orders"
FIFO = SQS + ".fifo"


def field(name, value):
    path = "/properties/" + name
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=name, raw=str(value), value=value, evidence_ids=["e1"])],
                      selected_candidate_id=name)


def evaluate(arn, **properties):
    fields = [field("FunctionName", "processor")]
    if arn is not None:
        fields.append(field("EventSourceArn", arn))
    fields += [field(name, value) for name, value in properties.items()]
    resource = Resource(id="mapping", type="AWS::Lambda::EventSourceMapping",
                        name="mapping", scope=SCOPE, fields=fields)
    return {finding["rule_id"]: finding for finding in evaluate_lambda_event_source(resource)}


@pytest.mark.parametrize("arn", [KINESIS, DYNAMODB])
def test_stream_requires_starting_position(arn):
    result = evaluate(arn)
    assert result["LAMBDA_EVENT_SOURCE_STREAM_STARTING_POSITION"]["verdict"] == "FAIL"
    result = evaluate(arn, StartingPosition="LATEST")
    assert result["LAMBDA_EVENT_SOURCE_STREAM_STARTING_POSITION"]["verdict"] == "PASS"


def test_sqs_large_batch_requires_nonzero_window():
    result = evaluate(SQS, BatchSize=11)
    assert result["LAMBDA_EVENT_SOURCE_SQS_BATCH_WINDOW"]["verdict"] == "FAIL"
    result = evaluate(SQS, BatchSize=11, MaximumBatchingWindowInSeconds=1)
    assert result["LAMBDA_EVENT_SOURCE_SQS_BATCH_WINDOW"]["verdict"] == "PASS"
    result = evaluate(SQS, BatchSize=10)
    assert result["LAMBDA_EVENT_SOURCE_SQS_BATCH_WINDOW"]["verdict"] == "NOT_APPLICABLE"


def test_fifo_batch_maximum():
    result = evaluate(FIFO, BatchSize=11)
    assert result["LAMBDA_EVENT_SOURCE_SQS_FIFO_BATCH_SIZE"]["verdict"] == "FAIL"
    result = evaluate(FIFO, BatchSize=10)
    assert result["LAMBDA_EVENT_SOURCE_SQS_FIFO_BATCH_SIZE"]["verdict"] == "PASS"
    result = evaluate(FIFO)
    assert result["LAMBDA_EVENT_SOURCE_SQS_FIFO_BATCH_SIZE"]["verdict"] == "PASS"


def test_unknown_arn_does_not_guess_source():
    result = evaluate(None, BatchSize=11)
    assert all(finding["verdict"] == "NEEDS_REVIEW" for finding in result.values())
    assert all(finding["dependencies"] == ["/properties/EventSourceArn"]
               for finding in result.values())


def test_other_source_is_not_applicable():
    result = evaluate("arn:aws:kafka:ap-northeast-1:111111111111:cluster/orders/uuid")
    assert all(finding["verdict"] == "NOT_APPLICABLE" for finding in result.values())


def test_source_specific_property_scope_and_scaling_exclusion():
    mapping = Resource(id="mapping", type="AWS::Lambda::EventSourceMapping", name="mapping",
                       scope=SCOPE, fields=[field("EventSourceArn", SQS),
                                            field("TumblingWindowInSeconds", 20),
                                            field("ScalingConfig", {"MaximumConcurrency": 2}),
                                            field("ProvisionedPollerConfig", {"MinimumPollers": 2})])
    findings = evaluate_lambda_source_property_scope(mapping)
    assert any(row["path"] == "/properties/TumblingWindowInSeconds" and row["verdict"] == "FAIL"
               for row in findings)
    assert any(row["rule_id"] == "LAMBDA_EVENT_SOURCE_SCALING_MODE_EXCLUSIVE"
               and row["verdict"] == "FAIL" for row in findings)
    mapping.fields = [field("EventSourceArn", KINESIS), field("TumblingWindowInSeconds", 20)]
    assert evaluate_lambda_source_property_scope(mapping)[0]["verdict"] == "PASS"
    mapping.fields = [FieldValue(path="/properties/EventSourceArn", state=ValueState.UNRESOLVED),
                      field("TumblingWindowInSeconds", 20)]
    assert evaluate_lambda_source_property_scope(mapping)[0]["verdict"] == "NEEDS_REVIEW"


def test_sqs_provisioned_poller_lower_bounds():
    mapping = Resource(id="mapping", type="AWS::Lambda::EventSourceMapping", name="mapping",
                       scope=SCOPE, fields=[field("EventSourceArn", SQS),
                                            field("ProvisionedPollerConfig", {"MinimumPollers": 1,
                                                                               "MaximumPollers": 10})])
    findings = evaluate_lambda_source_property_scope(mapping)
    assert next(row for row in findings if row["rule_id"] == "LAMBDA_EVENT_SOURCE_SQS_POLLER_MINIMUM")["verdict"] == "FAIL"
    mapping.fields[-1] = field("ProvisionedPollerConfig", {"MinimumPollers": 2, "MaximumPollers": 10})
    findings = evaluate_lambda_source_property_scope(mapping)
    assert next(row for row in findings if row["rule_id"] == "LAMBDA_EVENT_SOURCE_SQS_POLLER_MINIMUM")["verdict"] == "PASS"
