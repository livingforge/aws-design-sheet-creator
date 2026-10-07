"""Seeded design defects for measuring detection on known-good templates.

Each operator copies a template and introduces one realistic design mistake at
the first eligible place. The catalog is chosen from common design mistakes,
not from the rules of this tool, so a defect the tool does not check counts as
a miss. Every defect is a defect by construction:

- deploy: AWS documents the value or combination as rejected or as failing.
- security: deploys, but violates an AWS Security Hub control.
- function: deploys, but the network path the design intends does not work.

`targets` lists the logical IDs a reviewer would point at; a finding on any of
them counts as detecting the defect.
"""
from __future__ import annotations

import copy
import ipaddress
from dataclasses import dataclass
from typing import Callable

from aws_design_sheet.cfn_template import _NO_VALUE, _contains_unresolved, _Resolver, _Unresolved


@dataclass(frozen=True)
class Mutation:
    template: dict
    targets: list[str]
    note: str


@dataclass(frozen=True)
class Operator:
    id: str
    kind: str
    category: str
    summary: str
    basis: str
    apply: Callable[["Context"], Mutation | None]


OPERATORS: list[Operator] = []


def operator(id: str, kind: str, category: str, summary: str, basis: str):
    def register(func):
        OPERATORS.append(Operator(id, kind, category, summary, basis, func))
        return func
    return register


class Context:
    """Read-only view of a template with values resolved like the importer does."""

    def __init__(self, template: dict, *, account: str, region: str):
        self.template = template
        self.resolver = _Resolver(template, account=account, region=region)
        self.resources = [(name, body) for name, body in template["Resources"].items()
                          if isinstance(body, dict) and self._active(body)
                          and isinstance(body.get("Properties", {}) or {}, dict)]
        self.types = {name: body.get("Type") for name, body in self.resources}

    def _active(self, body: dict) -> bool:
        condition = body.get("Condition")
        if condition is None:
            return True
        try:
            return self.resolver.condition(condition)
        except _Unresolved:
            return True

    def of_type(self, *types: str) -> list[tuple[str, dict]]:
        return [(name, body) for name, body in self.resources if body.get("Type") in types]

    def value(self, node):
        """Resolved value, or None when any part is unknown."""
        resolved = self.resolver.value(node)
        if resolved is _NO_VALUE or _contains_unresolved(resolved):
            return None
        return resolved

    def network(self, node) -> ipaddress.IPv4Network | None:
        resolved = self.value(node)
        try:
            network = ipaddress.ip_network(str(resolved), strict=True)
        except ValueError:
            return None
        return network if resolved is not None and network.version == 4 else None

    def ref(self, node) -> str | None:
        """Logical ID a Ref or Fn::GetAtt points to, when it is an active resource."""
        if isinstance(node, dict) and len(node) == 1:
            key, argument = next(iter(node.items()))
            target = None
            if key == "Ref":
                target = argument
            elif key == "Fn::GetAtt":
                target = argument[0] if isinstance(argument, list) else str(argument).split(".", 1)[0]
            if isinstance(target, str) and target in self.types:
                return target
        return None

    def copy(self) -> dict:
        return copy.deepcopy(self.template)

    def subnets_by_route(self) -> tuple[list[str], list[str]]:
        """Subnets whose route table sends 0.0.0.0/0 to an internet gateway, and the rest."""
        gateways = {name for name, _ in self.of_type("AWS::EC2::InternetGateway")}
        public_tables = {
            self.ref(props(body).get("RouteTableId"))
            for _, body in self.of_type("AWS::EC2::Route")
            if self.value(props(body).get("DestinationCidrBlock")) == "0.0.0.0/0"
            and self.ref(props(body).get("GatewayId")) in gateways}
        table_of = {self.ref(props(body).get("SubnetId")): self.ref(props(body).get("RouteTableId"))
                    for _, body in self.of_type("AWS::EC2::SubnetRouteTableAssociation")}
        subnets = [name for name, _ in self.of_type("AWS::EC2::Subnet") if table_of.get(name)]
        public = [name for name in subnets if table_of[name] in public_tables]
        return public, [name for name in subnets if name not in public]


def props(body: dict) -> dict:
    return body.get("Properties") or {}


def edit(template: dict, name: str) -> dict:
    """Mutable Properties of a resource in a copied template."""
    return template["Resources"][name].setdefault("Properties", {})


def first_list(ctx: Context, node, minimum: int) -> list | None:
    """A literal list of resource references with at least `minimum` items."""
    if isinstance(node, list) and len(node) >= minimum and all(ctx.ref(item) for item in node):
        return node
    return None


# --- deploy: AWS rejects the design -----------------------------------------------------

@operator("NET_SUBNET_OUTSIDE_VPC", "deploy", "network",
          "Subnet CIDR shifted out of its VPC CIDR (wrong octet)",
          "https://docs.aws.amazon.com/vpc/latest/userguide/subnet-sizing.html")
def subnet_outside_vpc(ctx: Context):
    for name, body in ctx.of_type("AWS::EC2::Subnet"):
        vpc = ctx.ref(props(body).get("VpcId"))
        if not vpc or ctx.types[vpc] != "AWS::EC2::VPC":
            continue
        vpc_net = ctx.network(dict(ctx.resources)[vpc]["Properties"].get("CidrBlock"))
        subnet = ctx.network(props(body).get("CidrBlock"))
        if not vpc_net or not subnet or not subnet.subnet_of(vpc_net):
            continue
        start = int(subnet.network_address) + vpc_net.num_addresses
        if start + subnet.num_addresses > 2 ** 32:
            continue
        moved = ipaddress.ip_network(f"{ipaddress.IPv4Address(start)}/{subnet.prefixlen}")
        template = ctx.copy()
        edit(template, name)["CidrBlock"] = str(moved)
        return Mutation(template, [name], f"{subnet} -> {moved}, VPC {vpc_net}")
    return None


@operator("NET_SUBNET_OVERLAP", "deploy", "network",
          "Subnet CIDR copied from another subnet in the same VPC",
          "https://docs.aws.amazon.com/vpc/latest/userguide/subnet-sizing.html")
def subnet_overlap(ctx: Context):
    seen: dict[str, tuple[str, ipaddress.IPv4Network]] = {}
    for name, body in ctx.of_type("AWS::EC2::Subnet"):
        vpc = ctx.ref(props(body).get("VpcId"))
        network = ctx.network(props(body).get("CidrBlock"))
        if not vpc or not network:
            continue
        if vpc in seen and seen[vpc][1] != network:
            template = ctx.copy()
            edit(template, name)["CidrBlock"] = str(seen[vpc][1])
            return Mutation(template, [name, seen[vpc][0]], f"{network} -> {seen[vpc][1]}")
        seen.setdefault(vpc, (name, network))
    return None


@operator("NET_VPC_ID_WRONG_REFERENCE", "deploy", "reference",
          "VpcId refers to another resource of the template by mistake",
          "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroup.html")
def vpc_id_wrong_reference(ctx: Context):
    candidates = [name for name, _ in ctx.of_type(
        "AWS::EC2::InternetGateway", "AWS::EC2::RouteTable", "AWS::EC2::Subnet", "AWS::EC2::SecurityGroup")]
    for name, body in ctx.of_type("AWS::EC2::SecurityGroup", "AWS::EC2::Subnet", "AWS::EC2::RouteTable"):
        vpc = ctx.ref(props(body).get("VpcId"))
        if not vpc or ctx.types[vpc] != "AWS::EC2::VPC":
            continue
        wrong = next((other for other in candidates if other != name), None)
        if wrong:
            template = ctx.copy()
            edit(template, name)["VpcId"] = {"Ref": wrong}
            return Mutation(template, [name], f"VpcId Ref {vpc} -> {wrong} ({ctx.types[wrong]})")
    return None


def _drop_dependency(ctx: Context, resource_type: str, applies) -> Mutation | None:
    attachments = {name for name, _ in ctx.of_type("AWS::EC2::VPCGatewayAttachment")}
    for name, body in ctx.of_type(resource_type):
        depends = body.get("DependsOn")
        depends = [depends] if isinstance(depends, str) else list(depends or [])
        dropped = [item for item in depends if item in attachments]
        if dropped and applies(body):
            template = ctx.copy()
            kept = [item for item in depends if item not in attachments]
            if kept:
                template["Resources"][name]["DependsOn"] = kept
            else:
                template["Resources"][name].pop("DependsOn")
            return Mutation(template, [name], f"DependsOn {dropped} removed")
    return None


@operator("NET_ROUTE_GATEWAY_DEPENDENCY", "deploy", "ordering",
          "Route to the internet gateway loses DependsOn on the gateway attachment",
          "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-dependson.html")
def route_gateway_dependency(ctx: Context):
    gateways = {name for name, _ in ctx.of_type("AWS::EC2::InternetGateway")}
    return _drop_dependency(ctx, "AWS::EC2::Route",
                            lambda body: ctx.ref(props(body).get("GatewayId")) in gateways)


@operator("NET_EIP_GATEWAY_DEPENDENCY", "deploy", "ordering",
          "VPC Elastic IP loses DependsOn on the gateway attachment",
          "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-dependson.html")
def eip_gateway_dependency(ctx: Context):
    return _drop_dependency(ctx, "AWS::EC2::EIP", lambda body: True)


@operator("SG_CIDR_INVALID_PREFIX", "deploy", "security_group",
          "Security group rule CIDR typed with prefix /33",
          "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-securitygroup-ingress.html")
def sg_cidr_invalid_prefix(ctx: Context):
    for name, body in ctx.of_type("AWS::EC2::SecurityGroup"):
        for index, rule in enumerate(props(body).get("SecurityGroupIngress") or []):
            if isinstance(rule, dict) and ctx.network(rule.get("CidrIp")):
                template = ctx.copy()
                address = ctx.network(rule["CidrIp"]).network_address
                edit(template, name)["SecurityGroupIngress"][index]["CidrIp"] = f"{address}/33"
                return Mutation(template, [name], f"ingress {index} CidrIp {address}/33")
    for name, body in ctx.of_type("AWS::EC2::SecurityGroupIngress"):
        network = ctx.network(props(body).get("CidrIp"))
        if network:
            template = ctx.copy()
            edit(template, name)["CidrIp"] = f"{network.network_address}/33"
            return Mutation(template, [name], f"CidrIp {network.network_address}/33")
    return None


def _application_load_balancers(ctx: Context):
    for name, body in ctx.of_type("AWS::ElasticLoadBalancingV2::LoadBalancer"):
        if ctx.value(props(body).get("Type", "application")) == "application":
            yield name, body


@operator("ELB_ALB_SINGLE_SUBNET", "deploy", "load_balancer",
          "Application Load Balancer placed in a single subnet",
          "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html")
def alb_single_subnet(ctx: Context):
    for name, body in _application_load_balancers(ctx):
        subnets = first_list(ctx, props(body).get("Subnets"), 2)
        if subnets:
            template = ctx.copy()
            edit(template, name)["Subnets"] = subnets[:1]
            return Mutation(template, [name], f"Subnets {len(subnets)} -> 1")
    return None


@operator("ELB_HTTPS_LISTENER_NO_CERTIFICATE", "deploy", "load_balancer",
          "ALB listener switched to HTTPS without a certificate",
          "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html")
def https_listener_no_certificate(ctx: Context):
    albs = {name for name, _ in _application_load_balancers(ctx)}
    for name, body in ctx.of_type("AWS::ElasticLoadBalancingV2::Listener"):
        if ctx.ref(props(body).get("LoadBalancerArn")) in albs and not props(body).get("Certificates"):
            template = ctx.copy()
            listener = edit(template, name)
            listener["Protocol"], listener["Port"] = "HTTPS", 443
            return Mutation(template, [name], "Protocol HTTPS, Port 443, no Certificates")
    return None


@operator("ASG_MIN_GREATER_THAN_MAX", "deploy", "autoscaling",
          "Auto Scaling group MinSize and MaxSize swapped",
          "https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-capacity-limits.html")
def asg_min_greater_than_max(ctx: Context):
    for name, body in ctx.of_type("AWS::AutoScaling::AutoScalingGroup"):
        low, high = (ctx.value(props(body).get(key)) for key in ("MinSize", "MaxSize"))
        try:
            low, high = int(low), int(high)
        except (TypeError, ValueError):
            continue
        new_min, new_max = (high, low) if low < high else (high + 1, high)
        template = ctx.copy()
        group = edit(template, name)
        group["MinSize"], group["MaxSize"] = str(new_min), str(new_max)
        group.pop("DesiredCapacity", None)
        return Mutation(template, [name], f"MinSize {new_min}, MaxSize {new_max}")
    return None


@operator("RDS_SUBNET_GROUP_SINGLE_SUBNET", "deploy", "database",
          "DB subnet group left with a single subnet",
          "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html")
def rds_subnet_group_single_subnet(ctx: Context):
    for name, body in ctx.of_type("AWS::RDS::DBSubnetGroup"):
        subnets = first_list(ctx, props(body).get("SubnetIds"), 2)
        if subnets:
            template = ctx.copy()
            edit(template, name)["SubnetIds"] = subnets[:1]
            return Mutation(template, [name], f"SubnetIds {len(subnets)} -> 1")
    return None


@operator("LAMBDA_TIMEOUT_OVER_LIMIT", "deploy", "lambda",
          "Lambda timeout set to 30 minutes",
          "https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html")
def lambda_timeout_over_limit(ctx: Context):
    for name, _ in ctx.of_type("AWS::Lambda::Function"):
        template = ctx.copy()
        edit(template, name)["Timeout"] = 1800
        return Mutation(template, [name], "Timeout 1800")
    return None


@operator("LAMBDA_DEPRECATED_RUNTIME", "deploy", "lambda",
          "Lambda runtime set to a deprecated version that blocks creation",
          "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html")
def lambda_deprecated_runtime(ctx: Context):
    for name, body in ctx.of_type("AWS::Lambda::Function"):
        runtime = ctx.value(props(body).get("Runtime"))
        old = ("python2.7" if str(runtime).startswith("python") else
               "nodejs12.x" if str(runtime).startswith("nodejs") else None)
        if old:
            template = ctx.copy()
            edit(template, name)["Runtime"] = old
            return Mutation(template, [name], f"Runtime {runtime} -> {old}")
    return None


@operator("SQS_FIFO_NAME_WITHOUT_SUFFIX", "deploy", "messaging",
          "Queue made FIFO while its name lacks the .fifo suffix",
          "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sqs-queue.html")
def sqs_fifo_name(ctx: Context):
    for name, body in ctx.of_type("AWS::SQS::Queue"):
        if ctx.value(props(body).get("FifoQueue")) in (True, "true"):
            continue
        queue_name = ctx.value(props(body).get("QueueName"))
        if props(body).get("QueueName") is not None and not isinstance(queue_name, str):
            continue
        template = ctx.copy()
        queue = edit(template, name)
        queue["FifoQueue"] = True
        queue["QueueName"] = queue_name or f"{name.lower()}-queue"
        return Mutation(template, [name], f"FifoQueue true, QueueName {queue['QueueName']}")
    return None


@operator("SQS_VISIBILITY_TIMEOUT_OVER_LIMIT", "deploy", "messaging",
          "Queue visibility timeout set to one day",
          "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sqs-queue.html")
def sqs_visibility_timeout(ctx: Context):
    for name, _ in ctx.of_type("AWS::SQS::Queue"):
        template = ctx.copy()
        edit(template, name)["VisibilityTimeout"] = 86400
        return Mutation(template, [name], "VisibilityTimeout 86400")
    return None


@operator("DDB_KEY_ATTRIBUTE_UNDEFINED", "deploy", "database",
          "DynamoDB key attribute name differs in case from its definition",
          "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-table.html")
def ddb_key_attribute_undefined(ctx: Context):
    for name, body in ctx.of_type("AWS::DynamoDB::Table"):
        keys = props(body).get("KeySchema")
        if isinstance(keys, list) and keys and isinstance(keys[0], dict) \
                and isinstance(keys[0].get("AttributeName"), str):
            old = keys[0]["AttributeName"]
            new = old[0].swapcase() + old[1:]
            new = new if new != old else old + "X"
            template = ctx.copy()
            edit(template, name)["KeySchema"][0]["AttributeName"] = new
            return Mutation(template, [name], f"KeySchema {old} -> {new}")
    return None


@operator("DDB_ON_DEMAND_WITH_THROUGHPUT", "deploy", "database",
          "On-demand DynamoDB table keeps provisioned throughput",
          "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-table.html")
def ddb_on_demand_with_throughput(ctx: Context):
    for name, body in ctx.of_type("AWS::DynamoDB::Table"):
        template = ctx.copy()
        table = edit(template, name)
        table["BillingMode"] = "PAY_PER_REQUEST"
        table.setdefault("ProvisionedThroughput", {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5})
        return Mutation(template, [name], "BillingMode PAY_PER_REQUEST with ProvisionedThroughput")
    return None


@operator("S3_BUCKET_NAME_UPPERCASE", "deploy", "storage",
          "Bucket name written with uppercase letters",
          "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html")
def s3_bucket_name_uppercase(ctx: Context):
    for name, body in ctx.of_type("AWS::S3::Bucket"):
        current = props(body).get("BucketName")
        resolved = ctx.value(current) if current is not None else None
        if current is not None and not isinstance(resolved, str):
            continue
        new = (resolved[0].upper() + resolved[1:]) if resolved else f"{name}-Logs"
        if new == resolved:
            continue
        template = ctx.copy()
        edit(template, name)["BucketName"] = new
        return Mutation(template, [name], f"BucketName {new}")
    return None


@operator("CF_ACM_CERTIFICATE_REGION", "deploy", "cdn",
          "CloudFront uses an ACM certificate issued in ap-northeast-1",
          "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html")
def cloudfront_acm_region(ctx: Context):
    for name, body in ctx.of_type("AWS::CloudFront::Distribution"):
        config = props(body).get("DistributionConfig")
        viewer = config.get("ViewerCertificate") if isinstance(config, dict) else None
        if isinstance(viewer, dict) and "AcmCertificateArn" in viewer:
            template = ctx.copy()
            arn = "arn:aws:acm:ap-northeast-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            edit(template, name)["DistributionConfig"]["ViewerCertificate"]["AcmCertificateArn"] = arn
            return Mutation(template, [name], "AcmCertificateArn in ap-northeast-1")
    return None


@operator("IAM_INSTANCE_PROFILE_TWO_ROLES", "deploy", "iam",
          "Instance profile lists two roles",
          "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html")
def instance_profile_two_roles(ctx: Context):
    roles = [name for name, _ in ctx.of_type("AWS::IAM::Role")]
    for name, body in ctx.of_type("AWS::IAM::InstanceProfile"):
        listed = props(body).get("Roles")
        current = ctx.ref(listed[0]) if isinstance(listed, list) and len(listed) == 1 else None
        other = next((role for role in roles if role != current), None)
        if current and other:
            template = ctx.copy()
            edit(template, name)["Roles"].append({"Ref": other})
            return Mutation(template, [name], f"Roles [{current}, {other}]")
    return None


# --- security: deploys but violates a Security Hub control --------------------------------

@operator("SG_SSH_OPEN_TO_WORLD", "security", "security_group",
          "Security group opens SSH (22) to 0.0.0.0/0",
          "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html")
def sg_ssh_open_to_world(ctx: Context):
    for name, body in ctx.of_type("AWS::EC2::SecurityGroup"):
        rules = props(body).get("SecurityGroupIngress")
        if rules is not None and not isinstance(rules, list):
            continue
        if any(ctx.value(rule.get("CidrIp")) == "0.0.0.0/0" and
               str(ctx.value(rule.get("FromPort"))) in ("22", "-1", "0")
               for rule in rules or [] if isinstance(rule, dict)):
            continue
        template = ctx.copy()
        edit(template, name).setdefault("SecurityGroupIngress", []).append(
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"})
        return Mutation(template, [name], "ingress tcp 22 from 0.0.0.0/0 added")
    return None


@operator("S3_PUBLIC_ACCESS_BLOCK_DISABLED", "security", "storage",
          "Bucket public access block turned off",
          "https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html")
def s3_public_access_block_disabled(ctx: Context):
    for name, _ in ctx.of_type("AWS::S3::Bucket"):
        template = ctx.copy()
        edit(template, name)["PublicAccessBlockConfiguration"] = {
            "BlockPublicAcls": False, "BlockPublicPolicy": False,
            "IgnorePublicAcls": False, "RestrictPublicBuckets": False}
        return Mutation(template, [name], "all four settings false")
    return None


@operator("RDS_PUBLICLY_ACCESSIBLE", "security", "database",
          "DB instance made publicly accessible",
          "https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html")
def rds_publicly_accessible(ctx: Context):
    for name, body in ctx.of_type("AWS::RDS::DBInstance"):
        if ctx.value(props(body).get("PubliclyAccessible")) not in (True, "true"):
            template = ctx.copy()
            edit(template, name)["PubliclyAccessible"] = True
            return Mutation(template, [name], "PubliclyAccessible true")
    return None


@operator("RDS_STORAGE_UNENCRYPTED", "security", "database",
          "Encrypted DB instance storage switched to unencrypted",
          "https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html")
def rds_storage_unencrypted(ctx: Context):
    for name, body in ctx.of_type("AWS::RDS::DBInstance"):
        if ctx.value(props(body).get("StorageEncrypted")) in (True, "true"):
            template = ctx.copy()
            instance = edit(template, name)
            instance["StorageEncrypted"] = False
            instance.pop("KmsKeyId", None)
            return Mutation(template, [name], "StorageEncrypted false")
    return None


@operator("RDS_SINGLE_AZ", "security", "database",
          "Production DB instance switched from Multi-AZ to single AZ",
          "https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html")
def rds_single_az(ctx: Context):
    for name, body in ctx.of_type("AWS::RDS::DBInstance"):
        if ctx.value(props(body).get("MultiAZ")) in (True, "true"):
            template = ctx.copy()
            edit(template, name)["MultiAZ"] = False
            return Mutation(template, [name], "MultiAZ false")
    return None


@operator("IAM_ROLE_ADMIN_WILDCARD", "security", "iam",
          "Role gets an inline policy allowing * on *",
          "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html")
def iam_role_admin_wildcard(ctx: Context):
    for name, body in ctx.of_type("AWS::IAM::Role"):
        policies = props(body).get("Policies")
        if policies is not None and not isinstance(policies, list):
            continue
        template = ctx.copy()
        edit(template, name).setdefault("Policies", []).append({
            "PolicyName": "admin-all",
            "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}]}})
        return Mutation(template, [name], "inline Allow * on *")
    return None


# --- function: deploys, but the intended network path does not work -----------------------

@operator("NET_NAT_IN_PRIVATE_SUBNET", "function", "network",
          "NAT gateway placed in a subnet without a route to the internet gateway",
          "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html")
def nat_in_private_subnet(ctx: Context):
    public, private = ctx.subnets_by_route()
    for name, body in ctx.of_type("AWS::EC2::NatGateway"):
        current = ctx.ref(props(body).get("SubnetId"))
        if current in public and private and \
                ctx.value(props(body).get("ConnectivityType", "public")) == "public":
            template = ctx.copy()
            edit(template, name)["SubnetId"] = {"Ref": private[0]}
            return Mutation(template, [name], f"SubnetId {current} -> {private[0]}")
    return None


@operator("NET_PRIVATE_ROUTE_TO_IGW", "function", "network",
          "Private route table default route points at the internet gateway instead of NAT",
          "https://docs.aws.amazon.com/vpc/latest/userguide/configure-subnets.html")
def private_route_to_igw(ctx: Context):
    gateways = [name for name, _ in ctx.of_type("AWS::EC2::InternetGateway")]
    for name, body in ctx.of_type("AWS::EC2::Route"):
        if gateways and ctx.ref(props(body).get("NatGatewayId")) and \
                ctx.value(props(body).get("DestinationCidrBlock")) == "0.0.0.0/0":
            template = ctx.copy()
            route = edit(template, name)
            route.pop("NatGatewayId")
            route["GatewayId"] = {"Ref": gateways[0]}
            return Mutation(template, [name], f"NatGatewayId -> GatewayId {gateways[0]}")
    return None


@operator("ELB_INTERNET_FACING_IN_PRIVATE_SUBNETS", "function", "load_balancer",
          "Internet-facing ALB placed in private subnets",
          "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html")
def internet_facing_in_private_subnets(ctx: Context):
    public, private = ctx.subnets_by_route()
    for name, body in _application_load_balancers(ctx):
        subnets = first_list(ctx, props(body).get("Subnets"), 2)
        scheme = ctx.value(props(body).get("Scheme", "internet-facing"))
        if subnets and scheme == "internet-facing" and len(private) >= 2 and \
                all(ctx.ref(item) in public for item in subnets):
            template = ctx.copy()
            edit(template, name)["Subnets"] = [{"Ref": subnet} for subnet in private[:len(subnets)]]
            return Mutation(template, [name], f"Subnets -> {private[:len(subnets)]}")
    return None
