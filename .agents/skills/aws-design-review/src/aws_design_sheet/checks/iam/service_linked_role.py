"""Check duplicate service-linked role requests visible in the design."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check

RULE_ID = "IAM_SERVICE_LINKED_ROLE_DUPLICATE_REQUEST"
SERVICE_PATH = "/properties/AWSServiceName"
SUFFIX_PATH = "/properties/CustomSuffix"


SOURCES = {
    "IAM_SERVICE_LINKED_ROLE_DUPLICATE_REQUEST": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-servicelinkedrole.html"],
}


def _value(resource: Resource, path: str) -> tuple[str | None, bool]:
    field = resource.field(path)
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ("" if path == SUFFIX_PATH else None), path == SUFFIX_PATH
    if field.state != ValueState.KNOWN:
        return None, False
    value = field.selected().value
    return (value, True) if isinstance(value, str) and value else (None, False)


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(evidence for candidate in field.candidates for evidence in candidate.evidence_ids)]


@resource_check('AWS::IAM::ServiceLinkedRole')
def evaluate_iam_service_linked_role_duplicate(design: Design, resource: Resource) -> dict[str, Any]:
    evidence = [*_evidence(resource.field(SERVICE_PATH)),
                *_evidence(resource.field(SUFFIX_PATH))]

    def result(verdict: str, reason: str, dependencies: list[str] | None = None) -> dict[str, Any]:
        return {"rule_id": RULE_ID, "resource_id": resource.id, "path": SERVICE_PATH,
                "verdict": verdict, "reason": reason,
                "dependencies": dependencies or [], "evidence_ids": list(dict.fromkeys(evidence))}

    if resource.type != "AWS::IAM::ServiceLinkedRole":
        return result("NOT_APPLICABLE", "resource type does not match")
    service, service_known = _value(resource, SERVICE_PATH)
    suffix, suffix_known = _value(resource, SUFFIX_PATH)
    if not service_known or not suffix_known:
        return result("NEEDS_REVIEW", "service principal or custom suffix is unresolved",
                      [SERVICE_PATH, SUFFIX_PATH])

    for other in design.resources:
        if other.id == resource.id or other.type != resource.type:
            continue
        if other.scope.account != resource.scope.account:
            continue
        other_service, other_service_known = _value(other, SERVICE_PATH)
        other_suffix, other_suffix_known = _value(other, SUFFIX_PATH)
        if other_service_known and other_suffix_known and other_service == service and other_suffix == suffix:
            evidence.extend(_evidence(other.field(SERVICE_PATH)))
            evidence.extend(_evidence(other.field(SUFFIX_PATH)))
            return result("FAIL", f"duplicate request for service-linked role also appears in {other.id}")
    return result("NEEDS_REVIEW", "no duplicate appears in this design; existing roles and suffix support require account review",
                  [SERVICE_PATH, SUFFIX_PATH])
