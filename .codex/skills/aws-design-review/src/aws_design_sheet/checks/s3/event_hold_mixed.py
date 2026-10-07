"""Conservative mixed-unit S3 Object Lock event-hold comparison.

CloudFormation requires DefaultEventHold to be no longer than DefaultRetention:
https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-defaultretention.html
"""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check

RULE_ID = "S3_EVENT_HOLD_WITHIN_RETENTION_MIXED_UNITS"
PATH = "/properties/ObjectLockConfiguration"
RETENTION = PATH + "/Rule/DefaultRetention"


SOURCES = {
    "S3_EVENT_HOLD_WITHIN_RETENTION_MIXED_UNITS": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-defaultretention.html",
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html"],
}


def _days_range(duration: dict[str, Any]) -> tuple[int, int] | None:
    days = duration.get("Days")
    years = duration.get("Years")
    if isinstance(days, int) and not isinstance(days, bool) and years is None:
        return days, days
    if isinstance(years, int) and not isinstance(years, bool) and days is None:
        # Any span of n calendar years is between 365n and 366n days.
        return 365 * years, 366 * years
    return None


@resource_check('AWS::S3::Bucket')
def evaluate_s3_event_hold_mixed_units(design: Design, resource: Resource) -> dict[str, Any]:
    _ = design
    configuration = resource.field(PATH)
    evidence = [] if configuration is None else list(dict.fromkeys([
        *configuration.intent_evidence_ids,
        *(item for candidate in configuration.candidates for item in candidate.evidence_ids),
    ]))

    def result(verdict: str, reason: str, dependencies: list[str] | None = None) -> dict[str, Any]:
        return {"rule_id": RULE_ID, "resource_id": resource.id, "path": RETENTION + "/DefaultEventHold",
                "verdict": verdict, "reason": reason,
                "dependencies": dependencies or [], "evidence_ids": evidence}

    if resource.type != "AWS::S3::Bucket":
        return result("NOT_APPLICABLE", "resource type does not match")
    if configuration is None or configuration.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return result("NOT_APPLICABLE", "Object Lock configuration is absent")
    if configuration.state != ValueState.KNOWN:
        return result("NEEDS_REVIEW", "Object Lock configuration is unresolved", [PATH])
    value = configuration.selected().value
    if not isinstance(value, dict):
        return result("NEEDS_REVIEW", "Object Lock configuration is not an object", [PATH])
    rule = value.get("Rule")
    retention = rule.get("DefaultRetention") if isinstance(rule, dict) else None
    if not isinstance(retention, dict):
        return result("NOT_APPLICABLE", "default retention is absent")
    hold = retention.get("DefaultEventHold")
    if not isinstance(hold, dict):
        return result("NOT_APPLICABLE", "default event hold is absent")
    if not (("Days" in hold and "Years" in retention) or
            ("Years" in hold and "Days" in retention)):
        return result("NOT_APPLICABLE", "durations use the same unit or are incomplete")
    hold_range = _days_range(hold)
    retention_range = _days_range(retention)
    if hold_range is None or retention_range is None:
        return result("NEEDS_REVIEW", "mixed durations cannot be compared", [RETENTION])
    if hold_range[0] > retention_range[1]:
        return result("FAIL", "event hold exceeds retention for every possible year length")
    if hold_range[1] <= retention_range[0]:
        return result("PASS", "event hold does not exceed retention for any possible year length")
    return result("NEEDS_REVIEW", "the boundary depends on the interpretation of a year",
                  [RETENTION])
