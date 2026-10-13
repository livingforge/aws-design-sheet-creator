"""Design-local IAM physical-name uniqueness; account inventory remains external.

AWS says IAM user, group, and role names are account-wide and case-insensitive:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html
"""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check

RULE_ID = "IAM_EXPLICIT_NAME_ACCOUNT_UNIQUE"
NAME_PATHS = {
    "AWS::IAM::Group": "/properties/GroupName",
    "AWS::IAM::Role": "/properties/RoleName",
    "AWS::IAM::User": "/properties/UserName",
}


SOURCES = {
    "IAM_EXPLICIT_NAME_ACCOUNT_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-group.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-role.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-user.html"],
}


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(item for candidate in field.candidates for item in candidate.evidence_ids)]


@resource_check('AWS::IAM::Group', 'AWS::IAM::Role', 'AWS::IAM::User')
def evaluate_iam_explicit_name_uniqueness(design: Design, resource: Resource) -> dict[str, Any]:
    path = NAME_PATHS.get(resource.type)

    def result(verdict: str, reason: str, *, evidence: list[str] | None = None,
               dependencies: list[str] | None = None) -> dict[str, Any]:
        return {"rule_id": RULE_ID, "resource_id": resource.id, "path": path,
                "verdict": verdict, "reason": reason,
                "dependencies": list(dict.fromkeys(dependencies or [])),
                "evidence_ids": list(dict.fromkeys(evidence or []))}

    if path is None:
        return result("NOT_APPLICABLE", "resource type does not match")
    name_field = resource.field(path)
    if name_field is None or name_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return result("NOT_APPLICABLE", "CloudFormation generates the physical name")
    evidence = _evidence(name_field)
    if name_field.state != ValueState.KNOWN:
        return result("NEEDS_REVIEW", "explicit IAM name is unresolved",
                      evidence=evidence, dependencies=[path])
    name = name_field.selected().value
    if not isinstance(name, str) or not name:
        return result("NEEDS_REVIEW", "explicit IAM name is not a resolved string",
                      evidence=evidence, dependencies=[path])

    duplicates = []
    for other in design.resources:
        if other.id == resource.id or other.type != resource.type:
            continue
        if other.scope.account != resource.scope.account:
            continue
        other_field = other.field(path)
        if other_field is None or other_field.state != ValueState.KNOWN:
            continue
        other_name = other_field.selected().value
        if isinstance(other_name, str) and other_name.casefold() == name.casefold():
            duplicates.append(other)
            evidence.extend(_evidence(other_field))
    if duplicates:
        ids = ", ".join(sorted(other.id for other in duplicates))
        return result("FAIL", f"explicit IAM name collides within the account with {ids}",
                      evidence=evidence)
    return result("NEEDS_REVIEW", "no duplicate appears in this design; existing IAM account names are not available",
                  evidence=evidence, dependencies=[path])
