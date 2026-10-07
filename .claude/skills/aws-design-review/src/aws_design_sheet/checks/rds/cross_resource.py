"""Checks for these resource types:

- AWS::RDS::DBInstance
- AWS::RDS::DBSecurityGroupIngress
- AWS::RDS::DBShardGroup
- AWS::RDS::DBCluster
"""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check
from ..common.context import Context


SOURCES = {
    "RDS_SERVERLESS_V2_CLUSTER_CAPACITY": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-rds-dbcluster-serverlessv2scalingconfiguration.html"],
    "RDS_DB_SECURITY_GROUP_INGRESS_VPC_FIELDS": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbsecuritygroupingress.html"],
    "RDS_SHARD_GROUP_LIMITLESS_CLUSTER": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbshardgroup.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html",
        "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Concepts.AuroraFeaturesRegionsDBEngines.grids.html"],
    "RDS_DUAL_NETWORK_SUBNET_IPV6": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html"],
    "RDS_GLOBAL_WRITE_FORWARDING_MEMBERSHIP": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-globalcluster.html"],
}


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(item for candidate in field.candidates for item in candidate.evidence_ids)]


@resource_check('AWS::RDS::DBInstance')
def evaluate_rds_serverless_cluster_capacity(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    path = "/properties/DBInstanceClass"
    field = resource.field(path)
    ctx.evidence.extend(_evidence(field))
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ctx.finding("RDS_SERVERLESS_V2_CLUSTER_CAPACITY", path,
                           "NOT_APPLICABLE", "db.serverless class is not specified")
    if field.state != ValueState.KNOWN:
        ctx.dependencies.append(f"{resource.id}{path}")
        return ctx.finding("RDS_SERVERLESS_V2_CLUSTER_CAPACITY", path,
                           "NEEDS_REVIEW", "DB instance class is unresolved")
    if field.selected().value != "db.serverless":
        return ctx.finding("RDS_SERVERLESS_V2_CLUSTER_CAPACITY", path,
                           "NOT_APPLICABLE", "DB instance is not Aurora Serverless v2")
    cluster = ctx.target(resource, "/properties/DBClusterIdentifier", "AWS::RDS::DBCluster")
    if cluster is None:
        return ctx.finding("RDS_SERVERLESS_V2_CLUSTER_CAPACITY", "/properties/DBClusterIdentifier",
                           "NEEDS_REVIEW", "DB cluster is not linked in the design")
    capacity_field = cluster.field("/properties/ServerlessV2ScalingConfiguration")
    ctx.evidence.extend(_evidence(capacity_field))
    if capacity_field is None or capacity_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        children = [item for item in cluster.fields
                    if item.path.startswith("/properties/ServerlessV2ScalingConfiguration/")]
        ctx.evidence.extend(e for item in children for e in _evidence(item))
        if any(item.state == ValueState.KNOWN for item in children):
            verdict, reason = "PASS", "linked cluster has Serverless v2 capacity fields"
        elif children:
            verdict, reason = "NEEDS_REVIEW", "linked cluster capacity range is unresolved"
        else:
            verdict, reason = "FAIL", "linked cluster lacks ServerlessV2ScalingConfiguration"
    elif capacity_field.state != ValueState.KNOWN:
        ctx.dependencies.append(f"{cluster.id}/properties/ServerlessV2ScalingConfiguration")
        verdict, reason = "NEEDS_REVIEW", "linked cluster capacity range is unresolved"
    else:
        verdict, reason = "PASS", "linked cluster has a Serverless v2 capacity range"
    return ctx.finding("RDS_SERVERLESS_V2_CLUSTER_CAPACITY", "/properties/DBClusterIdentifier",
                       verdict, reason)


@resource_check('AWS::RDS::DBSecurityGroupIngress')
def evaluate_rds_db_security_group_ingress(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "RDS_DB_SECURITY_GROUP_INGRESS_VPC_FIELDS"
    path = "/properties/EC2SecurityGroupId"
    fields = {name: resource.field(f"/properties/{name}") for name in
              ("CIDRIP", "EC2SecurityGroupId", "EC2SecurityGroupName", "EC2SecurityGroupOwnerId")}
    if all(fields[name] is None or fields[name].state in (ValueState.MISSING, ValueState.NOT_APPLICABLE)
           for name in ("EC2SecurityGroupId", "EC2SecurityGroupName", "EC2SecurityGroupOwnerId")):
        return ctx.finding(rule, path, "NOT_APPLICABLE", "no EC2 security group authorization is specified")
    group = ctx.target(resource, "/properties/DBSecurityGroupName", "AWS::RDS::DBSecurityGroup")
    if group is None:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "DB security group is not linked in the design")
    vpc = group.field("/properties/EC2VpcId")
    if vpc is not None and vpc.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        if vpc.state != ValueState.KNOWN:
            ctx.dependencies.append(f"{group.id}/properties/EC2VpcId")
            return ctx.finding(rule, path, "NEEDS_REVIEW", "DB security group VPC is unresolved")
        ctx.evidence.extend(_evidence(vpc))
        required = ("EC2SecurityGroupId",)
    else:
        required = ("EC2SecurityGroupOwnerId",)
    for name in required:
        candidate = fields[name]
        if candidate is None or candidate.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
            return ctx.finding(rule, f"/properties/{name}", "FAIL", f"{name} is required for this DB security group")
        if candidate.state != ValueState.KNOWN:
            ctx.dependencies.append(f"{resource.id}/properties/{name}")
            return ctx.finding(rule, f"/properties/{name}", "NEEDS_REVIEW", f"{name} is unresolved")
        ctx.evidence.extend(_evidence(candidate))
    if not required == ("EC2SecurityGroupId",):
        if all(fields[name] is None or fields[name].state in (ValueState.MISSING, ValueState.NOT_APPLICABLE)
               for name in ("EC2SecurityGroupId", "EC2SecurityGroupName")):
            return ctx.finding(rule, path, "FAIL", "non-VPC DB security group also requires an EC2 security group name or ID")
    return ctx.finding(rule, path, "PASS", "EC2 security group fields match the linked DB security group")


@resource_check('AWS::RDS::DBShardGroup')
def evaluate_rds_shard_group_cluster(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "RDS_SHARD_GROUP_LIMITLESS_CLUSTER"
    path = "/properties/DBClusterIdentifier"
    cluster = ctx.target(resource, path, "AWS::RDS::DBCluster")
    if cluster is None:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "DB cluster is not linked in the design")
    engine = ctx.value(cluster, "/properties/Engine")
    scalability = ctx.value(cluster, "/properties/ClusterScalabilityType")
    if isinstance(engine, str) and engine != "aurora-postgresql":
        return ctx.finding(rule, path, "FAIL", "Aurora Limitless requires Aurora PostgreSQL")
    if scalability is None and cluster.field("/properties/ClusterScalabilityType") is None:
        return ctx.finding(rule, path, "FAIL", "DB cluster defaults to standard scalability")
    if isinstance(scalability, str) and scalability != "limitless":
        return ctx.finding(rule, path, "FAIL", "DB cluster is not configured for Aurora Limitless")
    if engine == "aurora-postgresql" and scalability == "limitless":
        return ctx.finding(rule, path, "PASS", "linked cluster uses Aurora Limitless")
    return ctx.finding(rule, path, "NEEDS_REVIEW", "DB cluster engine or scalability is unresolved")


@resource_check('AWS::RDS::DBInstance', 'AWS::RDS::DBCluster')
def evaluate_rds_network_type_subnets(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "RDS_DUAL_NETWORK_SUBNET_IPV6"
    path = "/properties/NetworkType"
    network_type = ctx.value(resource, path)
    if network_type is None and resource.field(path) is None:
        return ctx.finding(rule, path, "NOT_APPLICABLE", "NetworkType is not specified")
    if network_type == "IPV4":
        return ctx.finding(rule, path, "NOT_APPLICABLE", "dual-stack networking is not requested")
    if network_type != "DUAL":
        return ctx.finding(rule, path, "NEEDS_REVIEW", "NetworkType is unresolved")
    group = ctx.target(resource, "/properties/DBSubnetGroupName", "AWS::RDS::DBSubnetGroup")
    if group is None:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "DB subnet group is not linked in the design")
    subnet_ids = ctx.value(group, "/properties/SubnetIds")
    if not isinstance(subnet_ids, list) or not subnet_ids:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "DB subnet group subnets are unresolved")
    unknown = False
    for index in range(len(subnet_ids)):
        subnet = ctx.target(group, f"/properties/SubnetIds/{index}", "AWS::EC2::Subnet")
        if subnet is None:
            unknown = True
            continue
        native = ctx.value(subnet, "/properties/Ipv6Native")
        if native is True:
            return ctx.finding(rule, path, "FAIL", "IPv6-only subnet cannot support RDS dual-stack networking")
        direct = ctx.value(subnet, "/properties/Ipv6CidrBlock")
        if isinstance(direct, str):
            continue
        blocks = [block for block in design.resources
                  if block.type == "AWS::EC2::SubnetCidrBlock" and block.scope == subnet.scope and
                  any(ref.source_resource_id == block.id and ref.source_path == "/properties/SubnetId" and
                      ref.target_resource_id == subnet.id for ref in design.relations)]
        if not any(isinstance(ctx.value(block, "/properties/Ipv6CidrBlock"), str) for block in blocks):
            unknown = True
    return ctx.finding(rule, path, "NEEDS_REVIEW" if unknown else "PASS",
                       "one or more subnet IPv6 CIDRs are unresolved" if unknown else
                       "all linked DB subnets have IPv6 CIDRs")


@resource_check('AWS::RDS::DBCluster')
def evaluate_rds_global_write_forwarding(design: Design, resource: Resource) -> dict[str, Any]:
    ctx = Context(design, resource)
    rule = "RDS_GLOBAL_WRITE_FORWARDING_MEMBERSHIP"
    path = "/properties/EnableGlobalWriteForwarding"
    field = resource.field(path)
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return ctx.finding(rule, path, "NOT_APPLICABLE", "global write forwarding is not requested")
    forwarding = ctx.value(resource, path)
    if forwarding is False:
        return ctx.finding(rule, path, "NOT_APPLICABLE", "global write forwarding is disabled")
    if forwarding is not True:
        return ctx.finding(rule, path, "NEEDS_REVIEW", "global write forwarding setting is unresolved")
    engine = ctx.value(resource, "/properties/Engine")
    if isinstance(engine, str) and engine not in ("aurora-mysql", "aurora-postgresql"):
        return ctx.finding(rule, path, "FAIL", "global write forwarding requires an Aurora cluster")
    if not isinstance(engine, str):
        return ctx.finding(rule, path, "NEEDS_REVIEW", "DB cluster engine is unresolved")
    global_id = ctx.value(resource, "/properties/GlobalClusterIdentifier")
    if isinstance(global_id, str) and global_id:
        return ctx.finding(rule, path, "PASS", "cluster identifies an Aurora global database")
    if any(global_cluster.type == "AWS::RDS::GlobalCluster" and
           any(ref.source_resource_id == global_cluster.id and
               ref.source_path == "/properties/SourceDBClusterIdentifier" and
               ref.target_resource_id == resource.id for ref in design.relations)
           for global_cluster in design.resources):
        return ctx.finding(rule, path, "PASS", "cluster is linked as a global database primary")
    return ctx.finding(rule, path, "NEEDS_REVIEW", "global database membership is unresolved")
