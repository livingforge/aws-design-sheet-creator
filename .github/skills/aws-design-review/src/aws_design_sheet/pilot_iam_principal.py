"""Check Principal elements in IAM identity-based inline policies."""
from __future__ import annotations

import json
from typing import Any

from .models import Design, Resource, ValueState


RULE_ID = "IAM_IDENTITY_POLICY_NO_PRINCIPAL"
POLICY_PATH = "/properties/PolicyDocument"


def evaluate_iam_identity_policy_no_principal(design: Design, resource: Resource) -> dict[str, Any]:
    """Identity policies must not contain Principal or NotPrincipal statements."""
    _ = design  # Same evaluator signature as the other independent service rules.
    field = resource.field(POLICY_PATH)
    evidence = [] if field is None else list(dict.fromkeys([
        *field.intent_evidence_ids,
        *(item for candidate in field.candidates for item in candidate.evidence_ids)]))

    def result(verdict: str, reason: str, *, path: str = POLICY_PATH,
               dependencies: list[str] | None = None) -> dict[str, Any]:
        return {"rule_id": RULE_ID, "resource_id": resource.id, "path": path,
                "verdict": verdict, "reason": reason,
                "dependencies": dependencies or [], "evidence_ids": evidence}

    if resource.type != "AWS::IAM::Policy":
        return result("NOT_APPLICABLE", "resource type does not match")
    if field is None or field.state != ValueState.KNOWN:
        return result("NEEDS_REVIEW", "policy document is unresolved", dependencies=[POLICY_PATH])

    document = field.selected().value
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except (ValueError, TypeError):
            return result("NEEDS_REVIEW", "policy document cannot be parsed as JSON",
                          dependencies=[POLICY_PATH])
    if not isinstance(document, dict):
        return result("NEEDS_REVIEW", "policy document is not an object",
                      dependencies=[POLICY_PATH])
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        return result("NEEDS_REVIEW", "policy statements cannot be inspected",
                      dependencies=[POLICY_PATH + "/Statement"])

    malformed = []
    for index, statement in enumerate(statements):
        statement_path = POLICY_PATH + f"/Statement/{index}"
        if not isinstance(statement, dict):
            malformed.append(statement_path)
            continue
        for key in ("Principal", "NotPrincipal"):
            if key in statement:
                return result("FAIL", f"{key} is not allowed in an identity-based policy",
                              path=statement_path + "/" + key)
    if malformed:
        return result("NEEDS_REVIEW", "one or more policy statements cannot be inspected",
                      dependencies=malformed)
    return result("PASS", "no Principal or NotPrincipal appears in policy statements")
