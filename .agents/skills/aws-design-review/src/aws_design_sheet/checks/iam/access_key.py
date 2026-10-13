"""Validate an IAM access key's design-time user reference."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check

RULE_ID = "IAM_ACCESS_KEY_USER_REFERENCE"
PATH = "/properties/UserName"
USER_TYPE = "AWS::IAM::User"


SOURCES = {
    "IAM_ACCESS_KEY_USER_REFERENCE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-accesskey.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-user.html"],
}


@resource_check('AWS::IAM::AccessKey')
def evaluate_iam_access_key_user_reference(design: Design, resource: Resource) -> dict[str, Any]:
    field = resource.field(PATH)
    relations = [relation for relation in design.relations
                 if relation.source_resource_id == resource.id and relation.source_path == PATH]
    evidence = list(dict.fromkeys([
        *(item for relation in relations for item in relation.evidence_ids),
        *((item for candidate in field.candidates for item in candidate.evidence_ids)
          if field else ()),
        *(field.intent_evidence_ids if field else []),
    ]))

    def result(verdict: str, reason: str, dependencies: list[str] | None = None) -> dict[str, Any]:
        return {"rule_id": RULE_ID, "resource_id": resource.id, "path": PATH,
                "verdict": verdict, "reason": reason,
                "dependencies": dependencies or [], "evidence_ids": evidence}

    if resource.type != "AWS::IAM::AccessKey":
        return result("NOT_APPLICABLE", "resource type does not match")
    if field and field.state in (ValueState.CONFLICT, ValueState.INFERRED, ValueState.UNRESOLVED):
        return result("NEEDS_REVIEW", "user name is unresolved", [PATH])
    if field and field.state == ValueState.KNOWN and relations:
        return result("NEEDS_REVIEW", "user name has both a literal and a logical reference", [PATH])
    if len(relations) != 1:
        return result("NEEDS_REVIEW", "user reference is absent or ambiguous", [PATH])

    relation = relations[0]
    if relation.expected_target_type and relation.expected_target_type != USER_TYPE:
        return result("FAIL", "declared target type is not IAM User")
    by_id = {candidate.id: candidate for candidate in design.resources}
    target = by_id.get(relation.target_resource_id) if relation.target_resource_id else None
    if not target and relation.unresolved_name:
        matches = [candidate for candidate in design.resources
                   if candidate.name == relation.unresolved_name
                   and candidate.scope.account == resource.scope.account
                   and candidate.scope.environment == resource.scope.environment]
        if len(matches) == 1:
            target = matches[0]
        else:
            return result("NEEDS_REVIEW", "user name cannot be uniquely resolved", [PATH])
    if not target:
        return result("NEEDS_REVIEW", "referenced user is not in the design", [PATH])
    if target.type != USER_TYPE:
        return result("FAIL", "referenced resource is not IAM User")
    if target.scope.account != resource.scope.account:
        return result("FAIL", "IAM user belongs to a different account")
    if target.scope.environment != resource.scope.environment:
        return result("NEEDS_REVIEW", "IAM user belongs to another design environment", [PATH])
    return result("PASS", "IAM user reference resolves in the same account")
