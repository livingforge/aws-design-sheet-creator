"""Checks for AWS::IAM::Policy."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check


SOURCES = {
    "IAM_POLICY_ATTACHMENT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-policy.html"],
}


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return list(dict.fromkeys([*field.intent_evidence_ids,
                               *(e for candidate in field.candidates for e in candidate.evidence_ids)]))


def _result(rule: str, resource: Resource, path: str, verdict: str, reason: str,
            *, dependencies: list[str] | None = None,
            evidence_ids: list[str] | None = None) -> dict[str, Any]:
    return {"rule_id": rule, "resource_id": resource.id, "path": path,
            "verdict": verdict, "reason": reason,
            "dependencies": dependencies or [], "evidence_ids": evidence_ids or []}


def _relations(design: Design, resource: Resource, path: str):
    return [relation for relation in design.relations
            if relation.source_resource_id == resource.id and
            (relation.source_path == path or relation.source_path.startswith(path + "/"))]


@resource_check('AWS::IAM::Policy')
def evaluate_iam_policy_attachment(design: Design, resource: Resource) -> dict[str, Any]:
    """AWS::IAM::Policy needs at least one group, role, or user attachment."""
    rule = "IAM_POLICY_ATTACHMENT"
    path = "/properties"
    if resource.type != "AWS::IAM::Policy":
        return _result(rule, resource, path, "NOT_APPLICABLE", "resource type does not match")

    names = ("Groups", "Roles", "Users")
    pending: list[str] = []
    evidence: list[str] = []
    has_known_attachment = False
    has_unresolved_reference = False
    resources = {item.id: item for item in design.resources}
    expected = {"Groups": "AWS::IAM::Group", "Roles": "AWS::IAM::Role",
                "Users": "AWS::IAM::User"}
    for name in names:
        item_path = f"/properties/{name}"
        field = resource.field(item_path)
        evidence.extend(_evidence(field))
        references = _relations(design, resource, item_path)
        evidence.extend(e for ref in references for e in ref.evidence_ids)
        if field is not None:
            if field.state == ValueState.KNOWN:
                value = field.selected().value
                if isinstance(value, list) and value:
                    has_known_attachment = True
                elif not isinstance(value, list):
                    pending.append(item_path)  # The schema check reports the wrong type.
            elif field.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
                pending.append(item_path)
        for ref in references:
            target = resources.get(ref.target_resource_id)
            if target and target.type == expected[name] and target.scope == resource.scope:
                has_known_attachment = True
            else:
                has_unresolved_reference = True
                pending.append(ref.source_path)

    evidence = list(dict.fromkeys(evidence))
    if has_known_attachment:
        return _result(rule, resource, path, "PASS", "at least one attachment target is specified",
                       evidence_ids=evidence)
    if pending:
        return _result(rule, resource, path, "NEEDS_REVIEW", "attachment target is unresolved",
                       dependencies=list(dict.fromkeys(pending)), evidence_ids=evidence)
    return _result(rule, resource, path, "FAIL", "Groups, Roles, or Users must contain an attachment target",
                   evidence_ids=evidence)
