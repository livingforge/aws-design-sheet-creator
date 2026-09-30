"""AIOps investigation groups are limited to one per account and Region."""
from __future__ import annotations

from .models import Design


def evaluate_aiops_investigation_group_uniqueness(design: Design) -> list[dict]:
    groups: dict[tuple[str, str], list] = {}
    for resource in design.resources:
        if resource.type == "AWS::AIOps::InvestigationGroup":
            groups.setdefault((resource.scope.account, resource.scope.region), []).append(resource)
    findings = []
    for resources in groups.values():
        duplicate = len(resources) > 1
        for resource in resources:
            findings.append({
                "rule_id": "AIOPS_INVESTIGATION_GROUP_REGION_UNIQUE",
                "resource_id": resource.id, "path": None,
                "verdict": "FAIL" if duplicate else "PASS",
                "reason": "multiple investigation groups in one account and Region" if duplicate else
                          "one investigation group in account and Region",
                "actual": [item.id for item in resources],
                "dependencies": [], "evidence_ids": [],
            })
    return findings
