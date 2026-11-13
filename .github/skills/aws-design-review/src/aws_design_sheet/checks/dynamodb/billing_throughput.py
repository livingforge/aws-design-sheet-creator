"""DynamoDB table billing mode and provisioned throughput."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN

RULE = "DYNAMODB_TABLE_BILLING_THROUGHPUT"
TYPE = "AWS::DynamoDB::Table"
BILLING = "/properties/BillingMode"
THROUGHPUT = "/properties/ProvisionedThroughput"


GSI_RULE = "DYNAMODB_GSI_BILLING_THROUGHPUT"
GSIS = "/properties/GlobalSecondaryIndexes"


SOURCES = {
    "DYNAMODB_TABLE_BILLING_THROUGHPUT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-table.html"],
    "DYNAMODB_GSI_BILLING_THROUGHPUT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-globalsecondaryindex.html",
        "https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_GlobalSecondaryIndex.html"],
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
    GlobalSecondaryIndexes are checked by DYNAMODB_GSI_BILLING_THROUGHPUT;
    OnDemandThroughput is outside both rules.
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


@resource_check('AWS::DynamoDB::Table')
def evaluate_dynamodb_gsi_billing_throughput(design: Design, resource: Resource) -> list[dict[str, Any]]:
    """Check each global secondary index's ProvisionedThroughput against the table's BillingMode.

    DynamoDB requires an index's own ProvisionedThroughput on a provisioned table and
    CloudFormation refuses it on a PAY_PER_REQUEST table ("Property ProvisionedThroughput
    can't be used with PAY_PER_REQUEST BillingMode"); cfn-lint 1.57.2 reports neither.
    An omitted BillingMode uses the documented PROVISIONED default.
    """
    ctx = _Context(design, resource)
    indexes = value(ctx, resource, GSIS)
    if not isinstance(indexes, list):
        return []  # absent, or an unresolved list that schema review already reports
    billing = value(ctx, resource, BILLING)
    mode = "PROVISIONED" if billing is ABSENT else billing
    results = []
    for index in range(len(indexes)):
        local = _Context(design, resource)
        path = f"{GSIS}/{index}/ProvisionedThroughput"
        throughput = value(local, resource, path)
        if mode not in ("PROVISIONED", "PAY_PER_REQUEST"):
            verdict, reason = "NEEDS_REVIEW", "BillingMode is unresolved or not a recognized value"
        elif throughput is UNKNOWN:
            verdict, reason = "NEEDS_REVIEW", "the index's ProvisionedThroughput is unresolved"
        elif mode == "PROVISIONED":
            verdict, reason = (("FAIL", "a PROVISIONED table requires ProvisionedThroughput on each global secondary index")
                               if throughput is ABSENT else
                               ("PASS", "the index of a PROVISIONED table has ProvisionedThroughput"))
        else:
            verdict, reason = (("PASS", "the index of a PAY_PER_REQUEST table omits ProvisionedThroughput")
                               if throughput is ABSENT else
                               ("FAIL", "a PAY_PER_REQUEST table cannot specify ProvisionedThroughput on a global secondary index"))
        results.append(local.finding(GSI_RULE, path, verdict, reason))
    return results
