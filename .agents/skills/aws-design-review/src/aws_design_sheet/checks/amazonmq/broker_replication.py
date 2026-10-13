"""Checks for AWS::AmazonMQ::Broker."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check


SOURCES = {
    "AMAZONMQ_CRDR_PRIMARY_BROKER": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-amazonmq-broker.html"],
}


def _value(field: FieldValue | None):
    return field.selected().value if field and field.state == ValueState.KNOWN else None


def _evidence(*fields: FieldValue | None) -> list[str]:
    return list(dict.fromkeys(e for field in fields if field is not None
                              for e in [*field.intent_evidence_ids,
                                        *(e for candidate in field.candidates
                                          for e in candidate.evidence_ids)]))


def _result(rule: str, resource: Resource, path: str, verdict: str, reason: str,
            fields: tuple[FieldValue | None, ...], dependencies: list[str] | None = None) -> dict:
    return {"rule_id": rule, "resource_id": resource.id, "path": path,
            "verdict": verdict, "reason": reason, "evidence_ids": _evidence(*fields),
            "dependencies": dependencies or []}


@resource_check('AWS::AmazonMQ::Broker')
def evaluate_broker_replication_primary(resource: Resource) -> dict:
    mode_path = "/properties/DataReplicationMode"
    primary_path = "/properties/DataReplicationPrimaryBrokerArn"
    mode = resource.field(mode_path)
    primary = resource.field(primary_path)
    fields = (mode, primary)
    rule = "AMAZONMQ_CRDR_PRIMARY_BROKER"
    if mode is None or mode.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(rule, resource, primary_path, "NOT_APPLICABLE",
                       "CRDR replication is not explicitly selected", fields)
    if mode.state != ValueState.KNOWN:
        return _result(rule, resource, mode_path, "NEEDS_REVIEW",
                       "replication mode is unresolved", fields, [mode_path])
    if not isinstance(_value(mode), str) or _value(mode).upper() != "CRDR":
        return _result(rule, resource, primary_path, "NOT_APPLICABLE",
                       "replication mode is not CRDR", fields)
    if primary is None or primary.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(rule, resource, primary_path, "FAIL",
                       "CRDR requires a primary broker ARN", fields)
    if primary.state != ValueState.KNOWN:
        return _result(rule, resource, primary_path, "NEEDS_REVIEW",
                       "primary broker ARN is unresolved", fields, [primary_path])
    return _result(rule, resource, primary_path, "PASS",
                   "primary broker ARN is specified", fields)
