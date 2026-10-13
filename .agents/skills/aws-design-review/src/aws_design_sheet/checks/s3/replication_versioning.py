"""S3 bucket replication and versioning.

S3 replication may cross Regions and accounts. A target ID explicitly names a
design resource; name-only resolution is limited to the source scope.
"""
from __future__ import annotations

import re
from ...models import ValueState
from ..registry import resource_check

RULE = "S3_REPLICATION_VERSIONING"
BUCKET = "AWS::S3::Bucket"
REPLICATION = "/properties/ReplicationConfiguration"
VERSIONING = "/properties/VersioningConfiguration"
STATUS = VERSIONING + "/Status"
TYPED_REFERENCE = re.compile(r"^@([^/]+)/([^/]+)$")


SOURCES = {
    "S3_REPLICATION_VERSIONING": [
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-requirements.html"],
}


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(e for candidate in field.candidates for e in candidate.evidence_ids)]


def _result(resource: Resource, path: str, verdict: str, reason: str,
            *, dependencies: list[str] = (), evidence_ids: list[str] = ()) -> dict[str, Any]:
    return {"rule_id": RULE, "resource_id": resource.id, "path": path,
            "verdict": verdict, "reason": reason,
            "dependencies": list(dict.fromkeys(dependencies)),
            "evidence_ids": list(dict.fromkeys(evidence_ids))}


def _status(resource: Resource) -> tuple[Any, list[str]]:
    nested = resource.field(STATUS)
    if nested is not None:
        if nested.state == ValueState.KNOWN:
            return nested.selected().value, _evidence(nested)
        return None, _evidence(nested)
    parent = resource.field(VERSIONING)
    if parent is None or parent.state != ValueState.KNOWN:
        return None, _evidence(parent)
    value = parent.selected().value
    if not isinstance(value, dict):
        return None, _evidence(parent)
    return value.get("Status"), _evidence(parent)


def _destinations(config: Any) -> list[tuple[str, Any]] | None:
    if not isinstance(config, dict) or not isinstance(config.get("Rules"), list) or not config["Rules"]:
        return None
    result = []
    for index, rule in enumerate(config["Rules"]):
        path = f"{REPLICATION}/Rules/{index}/Destination/Bucket"
        if not isinstance(rule, dict) or not isinstance(rule.get("Destination"), dict):
            return None
        result.append((path, rule["Destination"].get("Bucket")))
    return result


@resource_check('AWS::S3::Bucket')
def evaluate_s3_replication_versioning(design: Design, resource: Resource) -> dict[str, Any]:
    """Check source versioning and every design-resolved destination bucket."""
    if resource.type != BUCKET:
        return _result(resource, REPLICATION, "NOT_APPLICABLE", "resource type does not match")
    replication = resource.field(REPLICATION)
    if replication is None or replication.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(resource, REPLICATION, "NOT_APPLICABLE", "replication is not configured",
                       evidence_ids=_evidence(replication))
    if replication.state != ValueState.KNOWN:
        return _result(resource, REPLICATION, "NEEDS_REVIEW", "replication configuration is unresolved",
                       dependencies=[REPLICATION], evidence_ids=_evidence(replication))

    evidence = _evidence(replication)
    pending: list[str] = []
    failures: list[str] = []
    source_status, source_evidence = _status(resource)
    evidence.extend(source_evidence)
    if source_status is None:
        # The source is under our design and cannot replicate without this setting.
        source_field = resource.field(STATUS) or resource.field(VERSIONING)
        if source_field is None or source_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE, ValueState.KNOWN):
            failures.append("source bucket versioning is not enabled")
        else:
            pending.append(STATUS)
    elif source_status != "Enabled":
        failures.append("source bucket versioning is not Enabled")

    destinations = _destinations(replication.selected().value)
    if destinations is None:
        pending.append(REPLICATION + "/Rules")
    else:
        resources = {item.id: item for item in design.resources}
        for path, literal in destinations:
            references = [rel for rel in design.relations
                          if rel.source_resource_id == resource.id and rel.source_path == path]
            evidence.extend(e for ref in references for e in ref.evidence_ids)
            if len(references) != 1:
                pending.append(path)  # A literal ARN is not evidence of an in-design bucket.
                continue
            relation = references[0]
            literal_match = TYPED_REFERENCE.fullmatch(literal) if isinstance(literal, str) else None
            if not literal_match:
                pending.append(path)  # A relation must not silently override a different literal value.
                continue
            literal_type, literal_name = literal_match.groups()
            if literal_type != BUCKET:
                failures.append(f"{path}: declared destination is not {BUCKET}")
                continue
            if relation.expected_target_type and relation.expected_target_type != BUCKET:
                failures.append(f"{path}: declared target type is not {BUCKET}")
                continue
            if relation.unresolved_name and relation.unresolved_name != literal_name:
                pending.append(path)
                continue
            target = resources.get(relation.target_resource_id) if relation.target_resource_id else None
            if target is None and relation.unresolved_name:
                matches = [item for item in design.resources if item.type == BUCKET and
                           item.name == relation.unresolved_name and item.scope == resource.scope]
                if len(matches) == 1:
                    target = matches[0]
            if target is None:
                pending.append(path)
                continue
            if target.type != BUCKET:
                failures.append(f"{path}: target is not an S3 bucket")
                continue
            if target.name != literal_name:
                pending.append(path)
                continue
            # The explicit target ID is authoritative even across accounts/Regions.
            # A name-only reference was resolved above only within one scope.
            target_status, target_evidence = _status(target)
            evidence.extend(target_evidence)
            if target_status is None:
                pending.append(f"{target.id}:{STATUS}")
            elif target_status != "Enabled":
                failures.append(f"{path}: destination bucket versioning is not Enabled")

    if failures:
        return _result(resource, REPLICATION, "FAIL", "; ".join(failures),
                       dependencies=pending, evidence_ids=evidence)
    if pending:
        return _result(resource, REPLICATION, "NEEDS_REVIEW", "destination or versioning is unresolved",
                       dependencies=pending, evidence_ids=evidence)
    return _result(resource, REPLICATION, "PASS", "source and all design-resolved destinations have versioning Enabled",
                   evidence_ids=evidence)
