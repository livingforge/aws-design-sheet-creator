"""Checks for AWS::ARCRegionSwitch::Plan."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check


SOURCES = {
    "ARC_PLAN_DISTINCT_REGIONS": [
        "https://docs.aws.amazon.com/arc-region-switch/latest/api/API_CreatePlan.html"],
    "ARC_PLAN_PRIMARY_REGION_INCLUDED": [
        "https://docs.aws.amazon.com/arc-region-switch/latest/api/API_CreatePlan.html"],
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


@resource_check('AWS::ARCRegionSwitch::Plan')
def evaluate_region_switch_plan(resource: Resource) -> list[dict]:
    regions_path = "/properties/Regions"
    primary_path = "/properties/PrimaryRegion"
    regions_field = resource.field(regions_path)
    primary_field = resource.field(primary_path)
    regions = (regions_field.selected().value if regions_field and
               regions_field.state == ValueState.KNOWN else None)
    evidence = _evidence(regions_field, primary_field)
    results = []
    if isinstance(regions, list) and len(regions) == 2 and all(isinstance(r, str) for r in regions):
        distinct = regions[0] != regions[1]
        results.append(_result("ARC_PLAN_DISTINCT_REGIONS", resource, regions_path,
                               "PASS" if distinct else "FAIL",
                               "two different Regions are specified" if distinct else
                               "Region switch needs two different Regions", evidence))
    else:
        results.append(_result("ARC_PLAN_DISTINCT_REGIONS", resource, regions_path,
                               "NEEDS_REVIEW", "two Region values are unavailable",
                               evidence, [regions_path]))
    if primary_field is None or primary_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        results.append(_result("ARC_PLAN_PRIMARY_REGION_INCLUDED", resource, primary_path,
                               "NOT_APPLICABLE", "primary Region is not explicitly set", evidence))
    elif primary_field.state != ValueState.KNOWN or not isinstance(regions, list):
        results.append(_result("ARC_PLAN_PRIMARY_REGION_INCLUDED", resource, primary_path,
                               "NEEDS_REVIEW", "primary or plan Regions are unresolved",
                               evidence, [primary_path, regions_path]))
    else:
        primary = primary_field.selected().value
        included = isinstance(primary, str) and primary in regions
        results.append(_result("ARC_PLAN_PRIMARY_REGION_INCLUDED", resource, primary_path,
                               "PASS" if included else "FAIL",
                               "primary Region is in the plan" if included else
                               "primary Region is outside the plan", evidence))
    return results
