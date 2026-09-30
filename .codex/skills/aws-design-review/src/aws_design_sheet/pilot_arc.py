"""Selected Region Switch and Zonal Autoshift conditions absent from the pinned schema."""
from __future__ import annotations

from .models import FieldValue, Resource, ValueState


def _evidence(*fields: FieldValue | None) -> list[str]:
    return list(dict.fromkeys(item for field in fields if field is not None
                              for item in [*field.intent_evidence_ids,
                                           *(e for candidate in field.candidates for e in candidate.evidence_ids)]))


def _result(rule: str, resource: Resource, path: str, verdict: str, reason: str,
            evidence: list[str], dependencies: list[str] | None = None) -> dict:
    return {"rule_id": rule, "resource_id": resource.id, "path": path,
            "verdict": verdict, "reason": reason, "evidence_ids": evidence,
            "dependencies": dependencies or []}


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
