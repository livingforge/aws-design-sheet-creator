"""Checks for AWS::ARCZonalShift::ZonalAutoshiftConfiguration."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check


SOURCES = {
    "ARC_ZONAL_AUTOSHIFT_PRACTICE_RUN": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-arczonalshift-zonalautoshiftconfiguration.html"],
}


def _evidence(*fields: FieldValue | None) -> list[str]:
    return list(dict.fromkeys(item for field in fields if field is not None
                              for item in [*field.intent_evidence_ids,
                                           *(e for candidate in field.candidates for e in candidate.evidence_ids)]))


def _result(rule: str, resource: Resource, path: str, verdict: str, reason: str,
            evidence: list[str], dependencies: list[str] | None = None) -> dict:
    return {"rule_id": rule, "resource_id": resource.id, "path": path,
            "verdict": verdict, "reason": reason, "evidence_ids": evidence,
            "dependencies": dependencies or []}


@resource_check('AWS::ARCZonalShift::ZonalAutoshiftConfiguration')
def evaluate_zonal_autoshift_practice_run(resource: Resource) -> dict:
    status_path = "/properties/ZonalAutoshiftStatus"
    practice_path = "/properties/PracticeRunConfiguration"
    status = resource.field(status_path)
    practice = resource.field(practice_path)
    evidence = _evidence(status, practice)
    rule = "ARC_ZONAL_AUTOSHIFT_PRACTICE_RUN"
    if status is None or status.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(rule, resource, practice_path, "NOT_APPLICABLE",
                       "zonal autoshift is not explicitly enabled", evidence)
    if status.state != ValueState.KNOWN:
        return _result(rule, resource, status_path, "NEEDS_REVIEW",
                       "zonal autoshift status is unresolved", evidence, [status_path])
    if status.selected().value != "ENABLED":
        return _result(rule, resource, practice_path, "NOT_APPLICABLE",
                       "zonal autoshift is not enabled", evidence)
    if practice is None or practice.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(rule, resource, practice_path, "FAIL",
                       "enabled zonal autoshift requires a practice run configuration", evidence)
    if practice.state != ValueState.KNOWN:
        return _result(rule, resource, practice_path, "NEEDS_REVIEW",
                       "practice run configuration is unresolved", evidence, [practice_path])
    return _result(rule, resource, practice_path, "PASS",
                   "practice run configuration is specified", evidence)
