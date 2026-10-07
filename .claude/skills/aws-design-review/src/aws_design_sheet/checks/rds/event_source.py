"""RDS event source type check for explicitly linked design resources."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check

RULE_ID = "RDS_EVENT_SUBSCRIPTION_SOURCE_TYPE"
SOURCE_TYPE = "/properties/SourceType"
SOURCE_IDS = "/properties/SourceIds"
TYPES = {
    "db-instance": "AWS::RDS::DBInstance",
    "db-cluster": "AWS::RDS::DBCluster",
    "db-parameter-group": "AWS::RDS::DBParameterGroup",
    "db-security-group": "AWS::RDS::DBSecurityGroup",
    "db-proxy": "AWS::RDS::DBProxy",
    "custom-engine-version": "AWS::RDS::CustomDBEngineVersion",
}


SOURCES = {
    "RDS_EVENT_SUBSCRIPTION_SOURCE_TYPE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-eventsubscription.html"],
}


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(id for candidate in field.candidates for id in candidate.evidence_ids)]


@resource_check('AWS::RDS::EventSubscription')
def evaluate_rds_event_source_type(design: Design, resource: Resource) -> dict[str, Any]:
    """Check only same-scope, resolved logical SourceIds; physical IDs need review."""
    source_field = resource.field(SOURCE_TYPE)
    ids_field = resource.field(SOURCE_IDS)
    refs = [ref for ref in design.relations
            if ref.source_resource_id == resource.id and ref.source_path.startswith(SOURCE_IDS + "/")]
    evidence = _evidence(source_field) + _evidence(ids_field)
    evidence.extend(id for ref in refs for id in ref.evidence_ids)
    dependencies: list[str] = []

    def result(verdict: str, reason: str) -> dict[str, Any]:
        return {"rule_id": RULE_ID, "resource_id": resource.id, "path": SOURCE_IDS,
                "verdict": verdict, "reason": reason,
                "dependencies": list(dict.fromkeys(dependencies)),
                "evidence_ids": list(dict.fromkeys(evidence))}

    if ids_field is None and not refs:
        return result("NOT_APPLICABLE", "SourceIds is absent")
    if ids_field and ids_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE) and not refs:
        return result("NOT_APPLICABLE", "SourceIds is absent")
    if source_field is None or source_field.state != ValueState.KNOWN:
        dependencies.append(SOURCE_TYPE)
        return result("NEEDS_REVIEW", "SourceType is unresolved")
    source_type = source_field.selected().value
    expected_type = TYPES.get(source_type) if isinstance(source_type, str) else None
    if expected_type is None:
        dependencies.append(SOURCE_TYPE)
        return result("NEEDS_REVIEW", "source type has no design resource mapping")
    if ids_field and ids_field.state not in (ValueState.KNOWN, ValueState.MISSING,
                                              ValueState.NOT_APPLICABLE):
        dependencies.append(SOURCE_IDS)
        return result("NEEDS_REVIEW", "SourceIds is unresolved")

    paths = {ref.source_path for ref in refs}
    if ids_field and ids_field.state == ValueState.KNOWN:
        values = ids_field.selected().value
        if not isinstance(values, list):
            dependencies.append(SOURCE_IDS)
            return result("NEEDS_REVIEW", "SourceIds has an invalid shape")
        paths.update(f"{SOURCE_IDS}/{index}" for index in range(len(values)))
    if not paths:
        return result("NOT_APPLICABLE", "SourceIds has no entries")

    by_id = {item.id: item for item in design.resources}
    mismatch = False
    for path in sorted(paths):
        index = path.removeprefix(SOURCE_IDS + "/")
        if not path.startswith(SOURCE_IDS + "/") or not index.isdigit():
            dependencies.append(path)
            continue
        matches = [ref for ref in refs if ref.source_path == path]
        if len(matches) != 1:
            dependencies.append(path)
            continue
        target = by_id.get(matches[0].target_resource_id)
        if target is None or target.scope != resource.scope:
            dependencies.append(path)
        elif target.type != expected_type:
            mismatch = True
    if mismatch:
        return result("FAIL", "SourceIds contains a resource of the wrong SourceType")
    if dependencies:
        return result("NEEDS_REVIEW", "one or more SourceIds cannot be resolved")
    return result("PASS", "all explicit SourceIds match SourceType")
