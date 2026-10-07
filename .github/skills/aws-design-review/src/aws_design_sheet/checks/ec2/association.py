"""VPC membership checks for explicitly linked EC2 subnet associations."""
from __future__ import annotations

from ..registry import resource_check

ASSOCIATIONS = {
    "AWS::EC2::SubnetRouteTableAssociation": (
        "EC2_SUBNET_ROUTE_TABLE_SAME_VPC", "RouteTableId", "AWS::EC2::RouteTable"),
    "AWS::EC2::SubnetNetworkAclAssociation": (
        "EC2_SUBNET_NETWORK_ACL_SAME_VPC", "NetworkAclId", "AWS::EC2::NetworkAcl"),
}
VPC_PATH = "/properties/VpcId"


SOURCES = {
    "EC2_SUBNET_ROUTE_TABLE_SAME_VPC": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnetroutetableassociation.html"],
    "EC2_SUBNET_NETWORK_ACL_SAME_VPC": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnetnetworkaclassociation.html",
        "https://docs.aws.amazon.com/vpc/latest/userguide/network-acl-associations.html"],
}


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(id for candidate in field.candidates for id in candidate.evidence_ids)]


@resource_check('AWS::EC2::SubnetRouteTableAssociation', 'AWS::EC2::SubnetNetworkAclAssociation')
def evaluate_ec2_subnet_association_vpc(design: Design, resource: Resource) -> dict[str, Any]:
    """Compare VPCs only when both association targets and their VPCs resolve."""
    rule_id, second_name, second_type = ASSOCIATIONS[resource.type]
    by_id = {item.id: item for item in design.resources}
    evidence: list[str] = []
    dependencies: list[str] = []
    vpc_ids: list[str] = []

    for name, expected_type in (("SubnetId", "AWS::EC2::Subnet"),
                                (second_name, second_type)):
        path = "/properties/" + name
        evidence.extend(_evidence(resource.field(path)))
        refs = [ref for ref in design.relations
                if ref.source_resource_id == resource.id and ref.source_path == path]
        evidence.extend(id for ref in refs for id in ref.evidence_ids)
        if len(refs) != 1:
            dependencies.append(path)
            continue
        target = by_id.get(refs[0].target_resource_id)
        if target is None or target.type != expected_type or target.scope != resource.scope:
            dependencies.append(path)
            continue
        evidence.extend(_evidence(target.field(VPC_PATH)))
        vpc_refs = [ref for ref in design.relations
                    if ref.source_resource_id == target.id and ref.source_path == VPC_PATH]
        evidence.extend(id for ref in vpc_refs for id in ref.evidence_ids)
        if len(vpc_refs) != 1:
            dependencies.append(path + " -> " + target.id + VPC_PATH)
            continue
        vpc = by_id.get(vpc_refs[0].target_resource_id)
        if vpc is None or vpc.type != "AWS::EC2::VPC" or vpc.scope != resource.scope:
            dependencies.append(path + " -> " + target.id + VPC_PATH)
            continue
        vpc_ids.append(vpc.id)

    if dependencies:
        verdict, reason = "NEEDS_REVIEW", "association VPC membership is unresolved"
    elif vpc_ids[0] != vpc_ids[1]:
        verdict, reason = "FAIL", "associated resources belong to different VPCs"
    else:
        verdict, reason = "PASS", "associated resources belong to the same VPC"
    return {"rule_id": rule_id, "resource_id": resource.id,
            "path": "/properties/" + second_name, "verdict": verdict,
            "reason": reason, "dependencies": dependencies,
            "evidence_ids": list(dict.fromkeys(evidence))}
