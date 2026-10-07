"""Validate known RDS backup and maintenance windows, including week wrap."""
from __future__ import annotations

import re
from ...models import ValueState
from ..registry import resource_check

DAYS = {name: index for index, name in enumerate(("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"))}
BACKUP = re.compile(r"^(\d{2}):(\d{2})-(\d{2}):(\d{2})$")
MAINTENANCE = re.compile(r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun):(\d{2}):(\d{2})-"
                         r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun):(\d{2}):(\d{2})$")


SOURCES = {
    "RDS_BACKUP_WINDOW_MINIMUM": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html"],
    "RDS_MAINTENANCE_WINDOW_MINIMUM": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html"],
    "RDS_BACKUP_MAINTENANCE_NONOVERLAP": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html"],
}


def _evidence(*fields: FieldValue | None) -> list[str]:
    return list(dict.fromkeys(id for field in fields if field
                              for id in (*field.intent_evidence_ids,
                                         *(item for candidate in field.candidates
                                           for item in candidate.evidence_ids))))


def _backup(value: str) -> tuple[int, int] | None:
    match = BACKUP.fullmatch(value)
    if not match:
        return None
    h1, m1, h2, m2 = map(int, match.groups())
    if max(h1, h2) > 23 or max(m1, m2) > 59:
        return None
    start, end = h1 * 60 + m1, h2 * 60 + m2
    return start, (end - start) % 1440


def _maintenance(value: str) -> tuple[int, int] | None:
    match = MAINTENANCE.fullmatch(value)
    if not match:
        return None
    d1, h1, m1, d2, h2, m2 = match.groups()
    h1, m1, h2, m2 = map(int, (h1, m1, h2, m2))
    if max(h1, h2) > 23 or max(m1, m2) > 59:
        return None
    start = DAYS[d1] * 1440 + h1 * 60 + m1
    end = DAYS[d2] * 1440 + h2 * 60 + m2
    return start, (end - start) % 10080


@resource_check('AWS::RDS::DBInstance', 'AWS::RDS::DBCluster')
def evaluate_rds_windows(resource: Resource) -> list[dict[str, Any]]:
    backup_path = "/properties/PreferredBackupWindow"
    maintenance_path = "/properties/PreferredMaintenanceWindow"
    backup_field, maintenance_field = resource.field(backup_path), resource.field(maintenance_path)
    results = []

    def finding(rule: str, path: str, verdict: str, reason: str,
                dependencies: list[str] | None = None):
        results.append({"rule_id": rule, "resource_id": resource.id, "path": path,
                        "verdict": verdict, "reason": reason,
                        "dependencies": dependencies or [],
                        "evidence_ids": _evidence(backup_field, maintenance_field)})

    parsed = {}
    for label, path, field, parser, rule in (
            ("backup", backup_path, backup_field, _backup, "RDS_BACKUP_WINDOW_MINIMUM"),
            ("maintenance", maintenance_path, maintenance_field, _maintenance,
             "RDS_MAINTENANCE_WINDOW_MINIMUM")):
        if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
            continue
        if field.state != ValueState.KNOWN or not isinstance(field.selected().value, str):
            finding(rule, path, "NEEDS_REVIEW", f"{label} window is unresolved", [path])
            continue
        interval = parser(field.selected().value)
        if interval is None or interval[1] < 30:
            finding(rule, path, "FAIL", f"{label} window needs a valid UTC format and at least 30 minutes")
            continue
        parsed[label] = interval
        finding(rule, path, "PASS", f"{label} window is at least 30 minutes")

    if "backup" in parsed and "maintenance" in parsed:
        backup_start, backup_duration = parsed["backup"]
        maintenance_start, maintenance_duration = parsed["maintenance"]
        maintenance_end = maintenance_start + maintenance_duration
        overlap = any(max(day * 1440 + backup_start, maintenance_start) <
                      min(day * 1440 + backup_start + backup_duration, maintenance_end)
                      for day in range(-1, 8))
        finding("RDS_BACKUP_MAINTENANCE_NONOVERLAP", backup_path,
                "FAIL" if overlap else "PASS",
                "backup and maintenance windows overlap" if overlap else "backup and maintenance windows do not overlap")
    elif backup_field and maintenance_field and ("backup" not in parsed or "maintenance" not in parsed):
        finding("RDS_BACKUP_MAINTENANCE_NONOVERLAP", backup_path,
                "NEEDS_REVIEW", "one or both windows cannot be compared", [backup_path, maintenance_path])
    return results
