"""Internet paths through route tables, for these resource types:

- AWS::EC2::NatGateway
- AWS::ElasticLoadBalancingV2::LoadBalancer
- AWS::ElasticLoadBalancing::LoadBalancer

A subnet is public when its associated route table sends 0.0.0.0/0 to an
internet gateway. These designs deploy but do not work: a public NAT gateway
or an internet-facing load balancer in a subnet without that route, and a NAT
gateway no route sends traffic to. A subnet without a route table association
in the design uses the VPC main route table, which the design does not
describe, so it needs review.
"""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check
from ..common.context import Context


VPC = "https://docs.aws.amazon.com/vpc/latest/userguide/"
SOURCES = {
    "EC2_NAT_GATEWAY_PUBLIC_SUBNET": [VPC + "vpc-nat-gateway.html", VPC + "VPC_Route_Tables.html"],
    "EC2_NAT_GATEWAY_ROUTED": [VPC + "nat-gateway-scenarios.html"],
    "ELB_INTERNET_FACING_PUBLIC_SUBNETS": [
        "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html",
        "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/network-load-balancers.html",
        VPC + "VPC_Route_Tables.html"],
}
PUBLIC, PRIVATE, UNKNOWN = "public", "not public", "unknown"


def _sources(design, resource, types: tuple[str, ...], path: str) -> list:
    """Resources of the given types in the same scope whose `path` relation targets `resource`."""
    found = []
    for item in design.resources:
        if item.type not in types or item.scope != resource.scope:
            continue
        refs = [ref for ref in design.relations if ref.source_resource_id == item.id and ref.source_path == path]
        if any(ref.target_resource_id == resource.id for ref in refs):
            found.append(item)
    return found


def _unresolved_link(design, resource, types: tuple[str, ...], path: str) -> bool:
    """Some resource of the given types could point at `resource` but its link is not resolved."""
    for item in design.resources:
        if item.type not in types or item.scope != resource.scope:
            continue
        refs = [ref for ref in design.relations if ref.source_resource_id == item.id and ref.source_path == path]
        field = item.field(path)
        if any(ref.target_resource_id is None for ref in refs) or (
                not refs and field is not None and field.state not in (ValueState.KNOWN, ValueState.MISSING,
                                                                       ValueState.NOT_APPLICABLE)):
            return True
    return False


def subnet_reach(ctx: Context, subnet) -> tuple[str, str]:
    """Whether the subnet's route table sends 0.0.0.0/0 to an internet gateway."""
    design = ctx.design
    associations = _sources(design, subnet, ("AWS::EC2::SubnetRouteTableAssociation",), "/properties/SubnetId")
    if len(associations) != 1:
        ctx.dependencies.append(f"{subnet.id} -> SubnetRouteTableAssociation")
        if not associations and not _unresolved_link(design, subnet, ("AWS::EC2::SubnetRouteTableAssociation",),
                                                     "/properties/SubnetId"):
            return UNKNOWN, f"subnet {subnet.name} uses the VPC main route table, which the design does not describe"
        return UNKNOWN, f"route table association of subnet {subnet.name} is unresolved"
    table = ctx.target(associations[0], "/properties/RouteTableId", "AWS::EC2::RouteTable")
    if table is None:
        return UNKNOWN, f"route table of subnet {subnet.name} is unresolved"
    unknown = _unresolved_link(design, table, ("AWS::EC2::Route",), "/properties/RouteTableId")
    for route in _sources(design, table, ("AWS::EC2::Route",), "/properties/RouteTableId"):
        destination = ctx.value(route, "/properties/DestinationCidrBlock")
        if destination is None:
            unknown = unknown or route.field("/properties/DestinationCidrBlock") is not None
            continue
        if destination != "0.0.0.0/0":
            continue
        refs = [ref for ref in design.relations
                if ref.source_resource_id == route.id and ref.source_path == "/properties/GatewayId"]
        ctx.evidence.extend(item for ref in refs for item in ref.evidence_ids)
        gateway = ctx.by_id.get(refs[0].target_resource_id) if len(refs) == 1 else None
        literal = ctx.value(route, "/properties/GatewayId") if not refs else None
        if gateway is not None and gateway.type == "AWS::EC2::InternetGateway" or \
                isinstance(literal, str) and literal.startswith("igw-"):
            return PUBLIC, f"subnet {subnet.name} routes 0.0.0.0/0 to an internet gateway"
        if refs and gateway is None:
            ctx.dependencies.append(f"{route.id}/properties/GatewayId")
            unknown = True
    if unknown:
        ctx.dependencies.append(f"{table.id} routes")
        return UNKNOWN, f"a route of the route table of subnet {subnet.name} is unresolved"
    return PRIVATE, f"route table of subnet {subnet.name} has no 0.0.0.0/0 route to an internet gateway"


@resource_check("AWS::EC2::NatGateway")
def evaluate_nat_gateway_paths(design, resource) -> list[dict]:
    findings = []
    ctx = Context(design, resource)
    connectivity = resource.field("/properties/ConnectivityType")
    mode = ctx.value(resource, "/properties/ConnectivityType") if connectivity else "public"
    path = "/properties/SubnetId"
    if mode == "private":
        findings.append(ctx.finding("EC2_NAT_GATEWAY_PUBLIC_SUBNET", path, "NOT_APPLICABLE",
                                    "private NAT gateway does not need an internet route"))
    elif mode != "public":
        findings.append(ctx.finding("EC2_NAT_GATEWAY_PUBLIC_SUBNET", path, "NEEDS_REVIEW",
                                    "connectivity type is unresolved"))
    else:
        subnet = ctx.target(resource, path, "AWS::EC2::Subnet")
        if subnet is None:
            findings.append(ctx.finding("EC2_NAT_GATEWAY_PUBLIC_SUBNET", path, "NEEDS_REVIEW",
                                        "subnet is not linked in the design"))
        else:
            reach, reason = subnet_reach(ctx, subnet)
            verdict = {PUBLIC: "PASS", PRIVATE: "FAIL", UNKNOWN: "NEEDS_REVIEW"}[reach]
            findings.append(ctx.finding("EC2_NAT_GATEWAY_PUBLIC_SUBNET", path, verdict, reason))

    routed = Context(design, resource)
    routes = _sources(design, resource, ("AWS::EC2::Route",), "/properties/NatGatewayId")
    if routes:
        verdict, reason = "PASS", "a route sends traffic to the NAT gateway"
    elif _unresolved_link(design, resource, ("AWS::EC2::Route",), "/properties/NatGatewayId"):
        routed.dependencies.append("AWS::EC2::Route /properties/NatGatewayId")
        verdict, reason = "NEEDS_REVIEW", "a route's NAT gateway is unresolved"
    else:
        verdict, reason = "FAIL", "no route in the design sends traffic to the NAT gateway"
    finding = routed.finding("EC2_NAT_GATEWAY_ROUTED", None, verdict, reason)
    finding["severity"] = "WARNING"
    findings.append(finding)
    return findings


@resource_check("AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancing::LoadBalancer")
def evaluate_internet_facing_subnets(design, resource) -> dict:
    ctx = Context(design, resource)
    rule = "ELB_INTERNET_FACING_PUBLIC_SUBNETS"
    kind = ctx.value(resource, "/properties/Type") if resource.field("/properties/Type") else "application"
    scheme = ctx.value(resource, "/properties/Scheme") if resource.field("/properties/Scheme") else "internet-facing"
    if kind == "gateway" or scheme == "internal":
        return ctx.finding(rule, "/properties/Scheme", "NOT_APPLICABLE", "load balancer is not internet-facing")
    if kind is None or scheme != "internet-facing":
        return ctx.finding(rule, "/properties/Scheme", "NEEDS_REVIEW", "load balancer type or scheme is unresolved")
    refs = [ref for ref in design.relations if ref.source_resource_id == resource.id and (
        ref.source_path.startswith("/properties/Subnets/") or
        ref.source_path.startswith("/properties/SubnetMappings/") and ref.source_path.endswith("/SubnetId"))]
    if not refs and not resource.field("/properties/Subnets") and not resource.field("/properties/SubnetMappings"):
        return ctx.finding(rule, "/properties/Subnets", "NOT_APPLICABLE",
                           "no subnets are specified (default VPC or Availability Zones only)")
    subnets = [ctx.target(resource, ref.source_path, "AWS::EC2::Subnet") for ref in refs]
    if not subnets or any(subnet is None for subnet in subnets):
        return ctx.finding(rule, "/properties/Subnets", "NEEDS_REVIEW", "subnets are not all linked in the design")
    reaches = [subnet_reach(ctx, subnet) for subnet in subnets]
    failed = [reason for reach, reason in reaches if reach == PRIVATE]
    if failed:
        return ctx.finding(rule, "/properties/Subnets", "FAIL", "; ".join(failed))
    if any(reach == UNKNOWN for reach, _ in reaches):
        return ctx.finding(rule, "/properties/Subnets", "NEEDS_REVIEW",
                           "; ".join(reason for reach, reason in reaches if reach == UNKNOWN))
    return ctx.finding(rule, "/properties/Subnets", "PASS", "every subnet routes 0.0.0.0/0 to an internet gateway")
