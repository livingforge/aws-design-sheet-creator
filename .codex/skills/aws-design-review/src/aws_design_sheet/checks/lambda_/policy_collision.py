"""Detect mixed Lambda permission resource types targeting one Lambda resource.

AWS CloudFormation warns that ResourcePolicy can overwrite Permission statements.
See https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-permission.html
"""
from __future__ import annotations

import re
from ...models import ValueState
from ..registry import resource_check

RULE_ID = "LAMBDA_PERMISSION_RESOURCE_POLICY_COLLISION"
PERMISSION = "AWS::Lambda::Permission"
POLICY = "AWS::Lambda::ResourcePolicy"
PATHS = {PERMISSION: "/properties/FunctionName", POLICY: "/properties/ResourceArn"}
FUNCTION = "AWS::Lambda::Function"
ARN = re.compile(r"^arn:([^:]+):lambda:([^:]+):(\d{12}):function:([^:]+)(?::([^:]+))?$")
PARTIAL = re.compile(r"^(?:(\d{12}):)?(?:function:)?([A-Za-z0-9_-]+)(?::([A-Za-z0-9_$.-]+))?$")


SOURCES = {
    "LAMBDA_PERMISSION_RESOURCE_POLICY_COLLISION": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-permission.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-resourcepolicy.html"],
}


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(item for candidate in field.candidates for item in candidate.evidence_ids)]


def _literal(value: str, resource: Resource) -> tuple[str | None, str, str, str, str | None] | None:
    """Return a comparable function identity for unambiguous Lambda naming forms."""
    full = ARN.fullmatch(value)
    if full:
        partition, region, account, function, qualifier = full.groups()
        return partition, region, account, function, qualifier
    partial = PARTIAL.fullmatch(value)
    if partial:
        account, function, qualifier = partial.groups()
        return None, resource.scope.region, account or resource.scope.account, function, qualifier
    return None


def _target(design: Design, resource: Resource) -> tuple[tuple[Any, ...] | None, list[str], list[str]]:
    path = PATHS[resource.type]
    field = resource.field(path)
    relations = [relation for relation in design.relations
                 if relation.source_resource_id == resource.id and relation.source_path == path]
    evidence = _evidence(field) + [item for relation in relations for item in relation.evidence_ids]
    if field and field.state in (ValueState.CONFLICT, ValueState.INFERRED, ValueState.UNRESOLVED):
        return None, [path], evidence
    if len(relations) > 1:
        return None, [path], evidence
    if relations:
        relation = relations[0]
        target = next((r for r in design.resources if r.id == relation.target_resource_id), None)
        if target is None and relation.unresolved_name:
            candidates = [r for r in design.resources if r.name == relation.unresolved_name
                          and r.scope == resource.scope]
            target = candidates[0] if len(candidates) == 1 else None
        if target is None or target.scope.account != resource.scope.account:
            return None, [path], evidence
        physical_name = target.field("/properties/FunctionName") if target.type == FUNCTION else None
        if physical_name and physical_name.state == ValueState.KNOWN:
            selected = physical_name.selected().value
            if isinstance(selected, str):
                identity = _literal(selected, target)
                if identity:
                    evidence.extend(_evidence(physical_name))
                    return ("literal", *identity), [], evidence
        # The resource identity is definitive even when CloudFormation generates its name.
        # A policy may target an alias or version, each of which has a separate policy.
        return ("resource", target.id), [], evidence
    if field is None or field.state != ValueState.KNOWN:
        return None, [path], evidence
    value = field.selected().value
    if not isinstance(value, str):
        return None, [path], evidence
    identity = _literal(value, resource)
    return (("literal", *identity), [], evidence) if identity else (None, [path], evidence)


@resource_check('AWS::Lambda::Permission')
def evaluate_lambda_permission_policy_collision(design: Design, resource: Resource) -> dict[str, Any]:
    path = PATHS[PERMISSION]

    def result(verdict: str, reason: str, dependencies: list[str] | None = None,
               evidence: list[str] | None = None) -> dict[str, Any]:
        return {"rule_id": RULE_ID, "resource_id": resource.id, "path": path,
                "verdict": verdict, "reason": reason,
                "dependencies": list(dict.fromkeys(dependencies or [])),
                "evidence_ids": list(dict.fromkeys(evidence or []))}

    if resource.type != PERMISSION:
        return result("NOT_APPLICABLE", "resource type does not match")
    policies = [r for r in design.resources if r.type == POLICY
                and r.scope.account == resource.scope.account and r.scope.region == resource.scope.region]
    if not policies:
        return result("NOT_APPLICABLE", "no Lambda ResourcePolicy is in this design")
    permission_target, dependencies, evidence = _target(design, resource)
    unresolved = bool(dependencies)
    for policy in policies:
        policy_target, policy_dependencies, policy_evidence = _target(design, policy)
        evidence.extend(policy_evidence)
        dependencies.extend(f"{policy.id}{item}" for item in policy_dependencies)
        if policy_dependencies:
            unresolved = True
        same = permission_target is not None and permission_target == policy_target
        if permission_target and policy_target and permission_target[0] == policy_target[0] == "literal":
            same = (permission_target[2:] == policy_target[2:]
                    and (permission_target[1] is None or policy_target[1] is None
                         or permission_target[1] == policy_target[1]))
        if same:
            return result("FAIL", f"{policy.id} uses ResourcePolicy for the same Lambda resource",
                          dependencies, evidence)
        if permission_target is None or policy_target is None:
            unresolved = True
        elif permission_target[0] != policy_target[0]:
            # A generated physical name cannot be compared safely to a literal ARN.
            unresolved = True
            dependencies.extend([path, f"{policy.id}{PATHS[POLICY]}"])
    if unresolved:
        return result("NEEDS_REVIEW", "one or more Lambda policy targets cannot be resolved",
                      dependencies, evidence)
    return result("PASS", "the two permission resource types target different Lambda resources",
                  evidence=evidence)
