"""DynamoDB table billing mode and provisioned throughput."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check

RULE = "DYNAMODB_TABLE_BILLING_THROUGHPUT"
TYPE = "AWS::DynamoDB::Table"
BILLING = "/properties/BillingMode"
THROUGHPUT = "/properties/ProvisionedThroughput"


SOURCES = {
    "DYNAMODB_TABLE_BILLING_THROUGHPUT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-table.html"],
}


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(e for candidate in field.candidates for e in candidate.evidence_ids)]


def _result(resource: Resource, verdict: str, reason: str, *,
            dependencies: list[str] = (), evidence_ids: list[str] = ()) -> dict[str, Any]:
    return {"rule_id": RULE, "resource_id": resource.id, "path": THROUGHPUT,
            "verdict": verdict, "reason": reason,
            "dependencies": list(dict.fromkeys(dependencies)),
            "evidence_ids": list(dict.fromkeys(evidence_ids))}


@resource_check('AWS::DynamoDB::Table')
def evaluate_dynamodb_table_billing_throughput(design: Design, resource: Resource) -> dict[str, Any]:
    """Check table-level ProvisionedThroughput against BillingMode.

    An omitted BillingMode uses the documented PROVISIONED default. Explicit
    unresolved/default intent is not replaced with that default in the model.
    GlobalSecondaryIndexes and OnDemandThroughput are outside this rule.
    """
    if resource.type != TYPE:
        return _result(resource, "NOT_APPLICABLE", "resource type does not match")

    billing = resource.field(BILLING)
    throughput = resource.field(THROUGHPUT)
    evidence = [*_evidence(billing), *_evidence(throughput)]
    if billing is None or billing.state == ValueState.MISSING:
        mode = "PROVISIONED"  # CloudFormation's documented default.
    elif billing.state != ValueState.KNOWN:
        return _result(resource, "NEEDS_REVIEW", "BillingMode is unresolved",
                       dependencies=[BILLING], evidence_ids=evidence)
    else:
        mode = billing.selected().value
        if mode not in ("PROVISIONED", "PAY_PER_REQUEST") or not isinstance(mode, str):
            return _result(resource, "NEEDS_REVIEW", "BillingMode is not a recognized value",
                           dependencies=[BILLING], evidence_ids=evidence)

    if throughput is not None and throughput.state not in (
            ValueState.KNOWN, ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(resource, "NEEDS_REVIEW", "ProvisionedThroughput is unresolved",
                       dependencies=[THROUGHPUT], evidence_ids=evidence)
    if throughput is not None and throughput.state == ValueState.KNOWN:
        value = throughput.selected().value
        if not isinstance(value, dict):
            return _result(resource, "NEEDS_REVIEW", "ProvisionedThroughput has an invalid shape",
                           dependencies=[THROUGHPUT], evidence_ids=evidence)
        supplied = True
    else:
        supplied = False

    if mode == "PROVISIONED":
        if supplied:
            return _result(resource, "PASS", "PROVISIONED mode has ProvisionedThroughput",
                           evidence_ids=evidence)
        return _result(resource, "FAIL", "PROVISIONED mode requires ProvisionedThroughput",
                       evidence_ids=evidence)
    if supplied:
        return _result(resource, "FAIL", "PAY_PER_REQUEST mode cannot specify ProvisionedThroughput",
                       evidence_ids=evidence)
    return _result(resource, "PASS", "PAY_PER_REQUEST mode omits ProvisionedThroughput",
                   evidence_ids=evidence)
