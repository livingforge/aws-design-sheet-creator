"""Lambda VPC membership rule for explicitly linked design resources."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check

RULE_ID = "LAMBDA_VPC_MEMBERSHIP"
VPC_CONFIG = "/properties/VpcConfig"
VPC_ID = "/properties/VpcId"
MEMBERS = {"SubnetIds": "AWS::EC2::Subnet",
           "SecurityGroupIds": "AWS::EC2::SecurityGroup"}


SOURCES = {
    "LAMBDA_VPC_MEMBERSHIP": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-function.html",
        "https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html"],
}


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(e for candidate in field.candidates for e in candidate.evidence_ids)]


def _result(resource: Resource, verdict: str, reason: str,
            dependencies: list[str], evidence_ids: list[str]) -> dict[str, Any]:
    return {"rule_id": RULE_ID, "resource_id": resource.id, "path": VPC_CONFIG,
            "verdict": verdict, "reason": reason,
            "dependencies": list(dict.fromkeys(dependencies)),
            "evidence_ids": list(dict.fromkeys(evidence_ids))}


@resource_check('AWS::Lambda::Function')
def evaluate_lambda_vpc_membership(design: Design, resource: Resource) -> dict[str, Any]:
    """Compare VPCs of every referenced subnet and security group in VpcConfig.

    Physical IDs alone do not establish membership; only resolved logical links do.
    """
    if resource.type != "AWS::Lambda::Function":
        return _result(resource, "NOT_APPLICABLE", "resource type does not match", [], [])

    config = resource.field(VPC_CONFIG)
    references = [r for r in design.relations
                  if r.source_resource_id == resource.id and
                  any(r.source_path.startswith(VPC_CONFIG + "/" + name + "/")
                      for name in MEMBERS)]
    if config is None and not references:
        return _result(resource, "NOT_APPLICABLE", "VPC configuration is not present", [], [])
    evidence = _evidence(config) + [e for ref in references for e in ref.evidence_ids]
    if config and config.state not in (ValueState.KNOWN, ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(resource, "NEEDS_REVIEW", "VPC configuration is unresolved",
                       [VPC_CONFIG], evidence)
    if config and config.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE) and not references:
        return _result(resource, "NOT_APPLICABLE", "VPC configuration is absent", [], evidence)

    values = config.selected().value if config and config.state == ValueState.KNOWN else None
    if values is not None and not isinstance(values, dict):
        return _result(resource, "NEEDS_REVIEW", "VPC configuration has an invalid shape",
                       [VPC_CONFIG], evidence)
    values = values or {}
    expected_paths: set[str] = set()
    dependencies: list[str] = []
    for name in MEMBERS:
        path = VPC_CONFIG + "/" + name
        items = values.get(name)
        if isinstance(items, list):
            expected_paths.update(f"{path}/{index}" for index in range(len(items)))
        elif items is not None:
            dependencies.append(path)
    expected_paths.update(ref.source_path for ref in references)
    if not expected_paths:
        return _result(resource, "NEEDS_REVIEW", "subnet and security group membership is not known",
                       [VPC_CONFIG], evidence)

    resources = {item.id: item for item in design.resources}
    refs_by_path = {}
    for ref in references:
        refs_by_path.setdefault(ref.source_path, []).append(ref)
    vpc_ids: set[str] = set()
    for path in sorted(expected_paths):
        parts = path.split("/")
        if len(parts) != 5 or parts[0:3] != ["", "properties", "VpcConfig"] or \
                parts[3] not in MEMBERS or not parts[4].isdigit():
            dependencies.append(path)
            continue
        refs = refs_by_path.get(path, [])
        if len(refs) != 1:
            dependencies.append(path)
            continue
        target = resources.get(refs[0].target_resource_id)
        if not target or target.type != MEMBERS[parts[3]] or target.scope != resource.scope:
            dependencies.append(path)
            continue
        vpc_refs = [r for r in design.relations
                    if r.source_resource_id == target.id and r.source_path == VPC_ID]
        evidence.extend(e for ref in vpc_refs for e in ref.evidence_ids)
        evidence.extend(_evidence(target.field(VPC_ID)))
        if len(vpc_refs) != 1:
            dependencies.append(path + " -> " + target.id + VPC_ID)
            continue
        vpc = resources.get(vpc_refs[0].target_resource_id)
        if not vpc or vpc.type != "AWS::EC2::VPC" or vpc.scope != resource.scope:
            dependencies.append(path + " -> " + target.id + VPC_ID)
            continue
        vpc_ids.add(vpc.id)

    if len(vpc_ids) > 1:
        return _result(resource, "FAIL", "subnets and security groups belong to different VPCs",
                       dependencies, evidence)
    if dependencies or not vpc_ids:
        return _result(resource, "NEEDS_REVIEW", "one or more VPC memberships are unresolved",
                       dependencies or [VPC_CONFIG], evidence)
    return _result(resource, "PASS", "all referenced subnets and security groups belong to one VPC",
                   [], evidence)
