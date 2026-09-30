"""IAM Access Analyzer conditions not expressed by the pinned resource schema."""
from __future__ import annotations

from .models import Resource, ValueState


def evaluate_analyzer_configuration_union(resource: Resource) -> dict:
    path = "/properties/AnalyzerConfiguration"
    field = resource.field(path)
    finding = {"rule_id": "ACCESS_ANALYZER_CONFIGURATION_UNION",
               "resource_id": resource.id, "path": path,
               "evidence_ids": [] if field is None else list(dict.fromkeys([
                   *field.intent_evidence_ids,
                   *(e for candidate in field.candidates for e in candidate.evidence_ids)])),
               "dependencies": []}
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return {**finding, "verdict": "NOT_APPLICABLE",
                "reason": "analyzer configuration is not explicitly specified"}
    if field.state != ValueState.KNOWN:
        return {**finding, "verdict": "NEEDS_REVIEW",
                "reason": "analyzer configuration is unresolved", "dependencies": [path]}
    configuration = field.selected().value
    if not isinstance(configuration, dict):
        return {**finding, "verdict": "NEEDS_REVIEW",
                "reason": "analyzer configuration is not an object", "dependencies": [path]}
    members = {"UnusedAccessConfiguration", "InternalAccessConfiguration"} & configuration.keys()
    if len(members) > 1:
        return {**finding, "verdict": "FAIL",
                "reason": "analyzer configuration union specifies both members"}
    if members:
        return {**finding, "verdict": "PASS",
                "reason": "analyzer configuration specifies one union member"}
    return {**finding, "verdict": "NOT_APPLICABLE",
            "reason": "analyzer configuration has no union member"}
