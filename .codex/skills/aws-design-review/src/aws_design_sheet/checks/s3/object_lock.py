"""Conditional S3 bucket Object Lock enablement rule."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check

RULE_ID = "S3_OBJECT_LOCK_CONFIGURATION_ENABLED"
CONFIG_PATH = "/properties/ObjectLockConfiguration"
ENABLED_PATH = "/properties/ObjectLockEnabled"


SOURCES = {
    "S3_OBJECT_LOCK_CONFIGURATION_ENABLED": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-bucket.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-objectlockconfiguration.html"],
}


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(item for candidate in field.candidates for item in candidate.evidence_ids)]


@resource_check('AWS::S3::Bucket')
def evaluate_s3_object_lock_configuration_enabled(
    design: Design, resource: Resource,
) -> dict[str, Any]:
    """Require bucket-level ObjectLockEnabled=true when configuration is supplied."""
    _ = design  # Kept for the common independent evaluator signature.
    configuration = resource.field(CONFIG_PATH)
    enabled = resource.field(ENABLED_PATH)
    evidence = list(dict.fromkeys([*_evidence(configuration), *_evidence(enabled)]))

    def result(verdict: str, reason: str, *, path: str = ENABLED_PATH,
               dependencies: list[str] | None = None) -> dict[str, Any]:
        return {"rule_id": RULE_ID, "resource_id": resource.id, "path": path,
                "verdict": verdict, "reason": reason,
                "dependencies": dependencies or [], "evidence_ids": evidence}

    if resource.type != "AWS::S3::Bucket":
        return result("NOT_APPLICABLE", "resource type does not match", path=CONFIG_PATH)
    if configuration is None or configuration.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return result("NOT_APPLICABLE", "Object Lock configuration is absent", path=CONFIG_PATH)
    if configuration.state != ValueState.KNOWN:
        return result("NEEDS_REVIEW", "Object Lock configuration is unresolved",
                      path=CONFIG_PATH, dependencies=[CONFIG_PATH])
    if enabled is None or enabled.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return result("FAIL", "ObjectLockEnabled must be true when ObjectLockConfiguration is set")
    if enabled.state != ValueState.KNOWN:
        return result("NEEDS_REVIEW", "ObjectLockEnabled is unresolved",
                      dependencies=[ENABLED_PATH])
    value = enabled.selected().value
    if value is True:
        return result("PASS", "Object Lock is enabled for the configured bucket")
    if value is False:
        return result("FAIL", "ObjectLockEnabled is false despite ObjectLockConfiguration")
    return result("NEEDS_REVIEW", "ObjectLockEnabled is not a known boolean",
                  dependencies=[ENABLED_PATH])
