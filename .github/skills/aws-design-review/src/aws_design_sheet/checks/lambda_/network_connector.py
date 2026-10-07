"""Checks for AWS::Lambda::NetworkConnector."""
from __future__ import annotations

from ..registry import resource_check
from ..common.context import Context


SOURCES = {
    "LAMBDA_NETWORK_CONNECTOR_SAME_VPC": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-networkconnector-vpcegressconfiguration.html"],
}


@resource_check('AWS::Lambda::NetworkConnector')
def evaluate_lambda_network_connector_vpc(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "LAMBDA_NETWORK_CONNECTOR_SAME_VPC"
    base = "/properties/Configuration/VpcEgressConfiguration"
    config = ctx.value(resource, base)
    if not isinstance(config, dict):
        parent = ctx.value(resource, "/properties/Configuration")
        config = parent.get("VpcEgressConfiguration") if isinstance(parent, dict) else None
    if not isinstance(config, dict):
        return ctx.finding(rule, base, "NEEDS_REVIEW", "VPC egress configuration is unresolved")
    subnet_ids = config.get("SubnetIds")
    security_group_ids = config.get("SecurityGroupIds", [])
    if not isinstance(subnet_ids, list) or not isinstance(security_group_ids, list):
        return ctx.finding(rule, base, "NEEDS_REVIEW", "subnet or security group IDs are unresolved")
    vpcs: set[str] = set()
    unknown = False
    for name, ids, resource_type in (("SubnetIds", subnet_ids, "AWS::EC2::Subnet"),
                                     ("SecurityGroupIds", security_group_ids, "AWS::EC2::SecurityGroup")):
        for index in range(len(ids)):
            path = f"{base}/{name}/{index}"
            target = ctx.target(resource, path, resource_type)
            vpc = ctx.target(target, "/properties/VpcId", "AWS::EC2::VPC") if target else None
            if vpc is None:
                unknown = True
            else:
                vpcs.add(vpc.id)
                if len(vpcs) > 1:
                    return ctx.finding(rule, path, "FAIL", "subnets and security groups span multiple VPCs")
    return ctx.finding(rule, base, "NEEDS_REVIEW" if unknown else "PASS",
                       "one or more VPC references are unresolved" if unknown else
                       "subnets and security groups share one VPC")
