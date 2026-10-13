"""Source-specific Lambda event source mapping constraints from a known ARN."""
from __future__ import annotations

import re
from ...models import ValueState
from ..registry import resource_check

ARN = "/properties/EventSourceArn"
START = "/properties/StartingPosition"
BATCH = "/properties/BatchSize"
WINDOW = "/properties/MaximumBatchingWindowInSeconds"
STREAM_RULE = "LAMBDA_EVENT_SOURCE_STREAM_STARTING_POSITION"
SQS_WINDOW_RULE = "LAMBDA_EVENT_SOURCE_SQS_BATCH_WINDOW"
SQS_FIFO_RULE = "LAMBDA_EVENT_SOURCE_SQS_FIFO_BATCH_SIZE"
SOURCE_PROPERTIES_RULE = "LAMBDA_EVENT_SOURCE_PROPERTY_SCOPE"
SCALING_EXCLUSIVE_RULE = "LAMBDA_EVENT_SOURCE_SCALING_MODE_EXCLUSIVE"
SQS_POLLER_MIN_RULE = "LAMBDA_EVENT_SOURCE_SQS_POLLER_MINIMUM"


SOURCES = {
    "LAMBDA_EVENT_SOURCE_STREAM_STARTING_POSITION": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"],
    "LAMBDA_EVENT_SOURCE_SQS_BATCH_WINDOW": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"],
    "LAMBDA_EVENT_SOURCE_SQS_FIFO_BATCH_SIZE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"],
    "LAMBDA_EVENT_SOURCE_PROPERTY_SCOPE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"],
    "LAMBDA_EVENT_SOURCE_SCALING_MODE_EXCLUSIVE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"],
    "LAMBDA_EVENT_SOURCE_SQS_POLLER_MINIMUM": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-provisionedpollerconfig.html"],
}


def _evidence(*fields: FieldValue | None) -> list[str]:
    values = []
    for field in fields:
        if field:
            values.extend(field.intent_evidence_ids)
            values.extend(id for candidate in field.candidates for id in candidate.evidence_ids)
    return list(dict.fromkeys(values))


def _value(field: FieldValue | None):
    return field.selected().value if field and field.state == ValueState.KNOWN else None


@resource_check('AWS::Lambda::EventSourceMapping')
def evaluate_lambda_event_source(resource: Resource) -> list[dict[str, Any]]:
    """Evaluate three source-specific conditions without guessing unresolved ARNs."""
    arn_field = resource.field(ARN)
    arn = _value(arn_field)
    source = None
    fifo = False
    if isinstance(arn, str):
        match = re.fullmatch(r"arn:[^:]+:([a-z0-9-]+):[^:]+:[0-9]{12}:(.+)", arn)
        if match:
            source = match.group(1)
            fifo = source == "sqs" and match.group(2).endswith(".fifo")
    results = []

    def append(rule: str, path: str, verdict: str, reason: str,
               fields: tuple[FieldValue | None, ...], dependencies: list[str] | None = None):
        results.append({"rule_id": rule, "resource_id": resource.id, "path": path,
                        "verdict": verdict, "reason": reason,
                        "evidence_ids": _evidence(arn_field, *fields),
                        "dependencies": dependencies or []})

    start_field = resource.field(START)
    if arn is None or not isinstance(arn, str) or source is None:
        append(STREAM_RULE, START, "NEEDS_REVIEW", "event source type is unresolved",
               (start_field,), [ARN])
    elif source in ("kinesis", "dynamodb"):
        if start_field is None or start_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
            append(STREAM_RULE, START, "FAIL", "stream source requires StartingPosition",
                   (start_field,))
        elif start_field.state != ValueState.KNOWN:
            append(STREAM_RULE, START, "NEEDS_REVIEW", "StartingPosition is unresolved",
                   (start_field,), [START])
        else:
            append(STREAM_RULE, START, "PASS", "stream source has StartingPosition",
                   (start_field,))
    else:
        append(STREAM_RULE, START, "NOT_APPLICABLE", "source is not a Kinesis or DynamoDB stream",
               (start_field,))

    batch_field, window_field = resource.field(BATCH), resource.field(WINDOW)
    if arn is None or not isinstance(arn, str) or source is None:
        append(SQS_WINDOW_RULE, WINDOW, "NEEDS_REVIEW", "event source type is unresolved",
               (batch_field, window_field), [ARN])
        append(SQS_FIFO_RULE, BATCH, "NEEDS_REVIEW", "queue type is unresolved",
               (batch_field,), [ARN])
    elif source != "sqs":
        append(SQS_WINDOW_RULE, WINDOW, "NOT_APPLICABLE", "source is not SQS",
               (batch_field, window_field))
        append(SQS_FIFO_RULE, BATCH, "NOT_APPLICABLE", "source is not SQS",
               (batch_field,))
    else:
        batch = _value(batch_field)
        window = _value(window_field)
        if batch_field and batch_field.state not in (ValueState.KNOWN, ValueState.MISSING,
                                                      ValueState.NOT_APPLICABLE):
            append(SQS_WINDOW_RULE, WINDOW, "NEEDS_REVIEW", "BatchSize is unresolved",
                   (batch_field, window_field), [BATCH])
        elif isinstance(batch, int) and not isinstance(batch, bool) and batch > 10:
            if window_field and window_field.state not in (ValueState.KNOWN, ValueState.MISSING,
                                                            ValueState.NOT_APPLICABLE):
                append(SQS_WINDOW_RULE, WINDOW, "NEEDS_REVIEW", "batch window is unresolved",
                       (batch_field, window_field), [WINDOW])
            else:
                append(SQS_WINDOW_RULE, WINDOW,
                       "PASS" if isinstance(window, int) and window >= 1 else "FAIL",
                       "SQS batches over 10 require a window of at least one second",
                       (batch_field, window_field))
        elif batch is None or isinstance(batch, int) and not isinstance(batch, bool):
            append(SQS_WINDOW_RULE, WINDOW, "NOT_APPLICABLE", "BatchSize does not exceed 10",
                   (batch_field, window_field))
        else:
            append(SQS_WINDOW_RULE, WINDOW, "NEEDS_REVIEW", "BatchSize has an invalid value",
                   (batch_field, window_field), [BATCH])

        if not fifo:
            append(SQS_FIFO_RULE, BATCH, "NOT_APPLICABLE", "source is a standard SQS queue",
                   (batch_field,))
        elif batch_field and batch_field.state not in (ValueState.KNOWN, ValueState.MISSING,
                                                        ValueState.NOT_APPLICABLE):
            append(SQS_FIFO_RULE, BATCH, "NEEDS_REVIEW", "BatchSize is unresolved",
                   (batch_field,), [BATCH])
        elif batch is None:
            append(SQS_FIFO_RULE, BATCH, "PASS", "default FIFO BatchSize is 10",
                   (batch_field,))
        elif isinstance(batch, int) and not isinstance(batch, bool):
            append(SQS_FIFO_RULE, BATCH, "PASS" if batch <= 10 else "FAIL",
                   "FIFO queue BatchSize must not exceed 10", (batch_field,))
        else:
            append(SQS_FIFO_RULE, BATCH, "NEEDS_REVIEW", "BatchSize has an invalid value",
                   (batch_field,), [BATCH])
    return results


@resource_check('AWS::Lambda::EventSourceMapping')
def evaluate_lambda_source_property_scope(resource: Resource) -> list[dict[str, Any]]:
    """Reject source-specific settings only when the event source is established."""
    arn_field = resource.field(ARN)
    arn = _value(arn_field)
    source = None
    if isinstance(arn, str):
        match = re.fullmatch(r"arn:[^:]+:([a-z0-9-]+):[^:]+:[0-9]{12}:.+", arn)
        if match:
            source = match.group(1)
    self_managed = resource.field("/properties/SelfManagedEventSource")
    if (source is None and (arn_field is None or arn_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE))
            and self_managed and self_managed.state == ValueState.KNOWN):
        source = "self-managed-kafka"
    allowed = {
        "BisectBatchOnFunctionError": {"kinesis", "dynamodb"},
        "ParallelizationFactor": {"kinesis", "dynamodb"},
        "TumblingWindowInSeconds": {"kinesis", "dynamodb"},
        "ScalingConfig": {"sqs"},
        "ProvisionedPollerConfig": {"sqs", "kafka", "self-managed-kafka"},
        "LoggingConfig": {"kafka", "self-managed-kafka"},
        "Queues": {"mq"},
    }
    results = []
    for name, sources in allowed.items():
        path = "/properties/" + name
        field = resource.field(path)
        if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
            continue
        if field.state != ValueState.KNOWN or source is None:
            verdict, reason, dependencies = "NEEDS_REVIEW", "event source or property is unresolved", [ARN, path]
        elif source in sources:
            verdict, reason, dependencies = "PASS", f"{name} applies to {source}", []
        else:
            verdict, reason, dependencies = "FAIL", f"{name} does not apply to {source}", []
        results.append({"rule_id": SOURCE_PROPERTIES_RULE, "resource_id": resource.id,
                        "path": path, "verdict": verdict, "reason": reason,
                        "dependencies": dependencies,
                        "evidence_ids": _evidence(arn_field, self_managed, field)})
    scaling = resource.field("/properties/ScalingConfig")
    provisioned = resource.field("/properties/ProvisionedPollerConfig")
    active = lambda field: field is not None and field.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE)
    if active(scaling) and active(provisioned):
        uncertain = scaling.state != ValueState.KNOWN or provisioned.state != ValueState.KNOWN
        results.append({"rule_id": SCALING_EXCLUSIVE_RULE, "resource_id": resource.id,
                        "path": "/properties/ProvisionedPollerConfig",
                        "verdict": "NEEDS_REVIEW" if uncertain else "FAIL",
                        "reason": "ScalingConfig and ProvisionedPollerConfig are mutually exclusive",
                        "dependencies": (["/properties/ScalingConfig", "/properties/ProvisionedPollerConfig"]
                                         if uncertain else []),
                        "evidence_ids": _evidence(scaling, provisioned)})
    if active(provisioned):
        config = _value(provisioned)
        if source is None or not isinstance(config, dict):
            verdict, reason, dependencies = "NEEDS_REVIEW", "poller settings or source are unresolved", [ARN, "/properties/ProvisionedPollerConfig"]
        elif source != "sqs":
            verdict, reason, dependencies = "NOT_APPLICABLE", "SQS poller minimum does not apply", []
        else:
            minimum = config.get("MinimumPollers", 2)
            maximum = config.get("MaximumPollers", 200)
            if not all(type(value) is int for value in (minimum, maximum)):
                verdict, reason, dependencies = "NEEDS_REVIEW", "SQS poller limits are unresolved", ["/properties/ProvisionedPollerConfig"]
            elif minimum < 2 or maximum < 2:
                verdict, reason, dependencies = "FAIL", "SQS requires at least two minimum and maximum pollers", []
            else:
                verdict, reason, dependencies = "PASS", "SQS poller minima are satisfied", []
        results.append({"rule_id": SQS_POLLER_MIN_RULE, "resource_id": resource.id,
                        "path": "/properties/ProvisionedPollerConfig",
                        "verdict": verdict, "reason": reason,
                        "dependencies": dependencies,
                        "evidence_ids": _evidence(arn_field, self_managed, provisioned)})
    return results
