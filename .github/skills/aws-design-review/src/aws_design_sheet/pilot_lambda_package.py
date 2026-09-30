"""Package-specific Lambda Function requirements absent from the pinned schema."""
from __future__ import annotations

from typing import Any

from .models import Design, Resource, ValueState


RULE_ID = "LAMBDA_PACKAGE_CONFIGURATION"
PACKAGE = "/properties/PackageType"
RUNTIME = "/properties/Runtime"
HANDLER = "/properties/Handler"
CODE = "/properties/Code"


def evaluate_lambda_package_configuration(design: Design, resource: Resource) -> dict[str, Any]:
    _ = design
    evidence = list(dict.fromkeys(
        item for field in resource.fields
        if field.path in (PACKAGE, RUNTIME, HANDLER, CODE) or field.path.startswith(CODE + "/")
        for item in [*field.intent_evidence_ids,
                     *(e for candidate in field.candidates for e in candidate.evidence_ids)]))

    def result(verdict: str, reason: str, path: str = PACKAGE,
               dependencies: list[str] | None = None) -> dict[str, Any]:
        return {"rule_id": RULE_ID, "resource_id": resource.id, "path": path,
                "verdict": verdict, "reason": reason,
                "dependencies": dependencies or [], "evidence_ids": evidence}

    if resource.type != "AWS::Lambda::Function":
        return result("NOT_APPLICABLE", "resource type does not match")
    package = resource.field(PACKAGE)
    if package is None or package.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return result("NEEDS_REVIEW", "package type is not explicit", dependencies=[PACKAGE])
    if package.state != ValueState.KNOWN:
        return result("NEEDS_REVIEW", "package type is unresolved", dependencies=[PACKAGE])
    mode = package.selected().value
    if mode not in ("Image", "Zip"):
        return result("NEEDS_REVIEW", "package type is outside the supported modes", dependencies=[PACKAGE])

    def prop(path: str) -> str:
        field = resource.field(path)
        if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
            return "absent"
        if field.state != ValueState.KNOWN:
            return "unknown"
        value = field.selected().value
        return "present" if isinstance(value, str) and bool(value.strip()) else "unknown"

    runtime = prop(RUNTIME)
    handler = prop(HANDLER)
    if mode == "Image" and runtime == "present":
        return result("FAIL", "container image functions cannot specify Runtime", RUNTIME)
    if mode == "Zip" and runtime == "absent":
        return result("FAIL", "Zip functions require Runtime", RUNTIME)
    if mode == "Zip" and handler == "absent":
        return result("FAIL", "Zip functions require Handler", HANDLER)

    code = resource.field(CODE)
    if code is None or code.state != ValueState.KNOWN:
        return result("NEEDS_REVIEW", "deployment code is unresolved", CODE, [CODE])
    contents = code.selected().value
    if not isinstance(contents, dict):
        return result("NEEDS_REVIEW", "deployment code has an invalid shape", CODE, [CODE])
    if mode == "Image":
        if not contents.get("ImageUri"):
            return result("FAIL", "Image functions require Code.ImageUri", CODE + "/ImageUri")
        if any(contents.get(key) for key in ("ZipFile", "S3Bucket", "S3Key")):
            return result("FAIL", "Image functions cannot use Zip deployment code", CODE)
    else:
        if contents.get("ImageUri"):
            return result("FAIL", "Zip functions cannot use Code.ImageUri", CODE + "/ImageUri")
        if not (contents.get("ZipFile") or (contents.get("S3Bucket") and contents.get("S3Key"))):
            return result("FAIL", "Zip functions require inline or S3 deployment code", CODE)
    dependencies = [path for path, state in ((RUNTIME, runtime), (HANDLER, handler))
                    if state == "unknown" and (mode == "Zip" or path == RUNTIME)]
    if dependencies:
        return result("NEEDS_REVIEW", "package configuration has unresolved fields",
                      dependencies=dependencies)
    return result("PASS", "package configuration matches its deployment type")
