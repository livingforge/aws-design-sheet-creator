"""SQS Queue encryption-option exclusivity.

AWS::SQS::Queue specifies that only one server-side encryption option can be
enabled per queue. The pinned schema types the two fields but has no condition
connecting them. This rule does not validate KMS key existence or permissions.
Source: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sqs-queue.html
"""
from __future__ import annotations

from typing import Any

from .models import Design, FieldValue, Resource, ValueState


RULE_ID = "SQS_QUEUE_ENCRYPTION_OPTION_EXCLUSIVE"
KMS_PATH = "/properties/KmsMasterKeyId"
SQS_PATH = "/properties/SqsManagedSseEnabled"


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(e for candidate in field.candidates for e in candidate.evidence_ids)]


def _result(resource: Resource, verdict: str, reason: str, *,
            dependencies: list[str] | None = None,
            evidence_ids: list[str] | None = None) -> dict[str, Any]:
    return {"rule_id": RULE_ID, "resource_id": resource.id, "path": SQS_PATH,
            "verdict": verdict, "reason": reason,
            "dependencies": dependencies or [], "evidence_ids": evidence_ids or []}


def evaluate_sqs_queue_encryption_option(design: Design, resource: Resource) -> dict[str, Any]:
    """Reject simultaneous SSE-KMS and SSE-SQS choices."""
    if resource.type != "AWS::SQS::Queue":
        return _result(resource, "NOT_APPLICABLE", "resource type does not match")

    key = resource.field(KMS_PATH)
    enabled = resource.field(SQS_PATH)
    key_refs = [relation for relation in design.relations
                if relation.source_resource_id == resource.id and relation.source_path == KMS_PATH]
    evidence = list(dict.fromkeys(_evidence(key) + _evidence(enabled) +
                                  [e for relation in key_refs for e in relation.evidence_ids]))

    if key and key_refs:
        return _result(resource, "NEEDS_REVIEW", "KMS key has conflicting literal and reference inputs",
                       dependencies=[KMS_PATH], evidence_ids=evidence)
    if key and key.state == ValueState.KNOWN:
        key_value = key.selected().value
        if not isinstance(key_value, str):
            return _result(resource, "NEEDS_REVIEW", "KMS key value has an invalid shape",
                           dependencies=[KMS_PATH], evidence_ids=evidence)
        kms_chosen = bool(key_value)
    elif key and key.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(resource, "NEEDS_REVIEW", "KMS key choice is unresolved",
                       dependencies=[KMS_PATH], evidence_ids=evidence)
    else:
        kms_chosen = len(key_refs) == 1
        if len(key_refs) > 1:
            return _result(resource, "NEEDS_REVIEW", "KMS key reference is ambiguous",
                           dependencies=[KMS_PATH], evidence_ids=evidence)

    if not kms_chosen:
        return _result(resource, "NOT_APPLICABLE", "SSE-KMS is not selected",
                       evidence_ids=evidence)
    if enabled is None or enabled.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(resource, "PASS", "SSE-KMS is selected without enabling SSE-SQS",
                       evidence_ids=evidence)
    if enabled.state != ValueState.KNOWN:
        return _result(resource, "NEEDS_REVIEW", "SSE-SQS choice is unresolved",
                       dependencies=[SQS_PATH], evidence_ids=evidence)
    value = enabled.selected().value
    if type(value) is not bool:
        return _result(resource, "NEEDS_REVIEW", "SSE-SQS value has an invalid shape",
                       dependencies=[SQS_PATH], evidence_ids=evidence)
    if value:
        return _result(resource, "FAIL", "SSE-KMS and SSE-SQS cannot both be enabled",
                       evidence_ids=evidence)
    return _result(resource, "PASS", "SSE-KMS is selected and SSE-SQS is disabled",
                   evidence_ids=evidence)
