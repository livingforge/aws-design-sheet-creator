"""Internet paths through route tables, for these resource types:

- AWS::EC2::NatGateway
- AWS::ElasticLoadBalancingV2::LoadBalancer
- AWS::ElasticLoadBalancing::LoadBalancer

A subnet's IPv4 fallback may consist of several CIDRs, not just 0.0.0.0/0.
Only complete, unambiguous IGW coverage establishes the path here. These
designs deploy but do not work: a public NAT gateway
or an internet-facing load balancer in a subnet without that route, and a NAT
gateway no route sends traffic to. A subnet without a route table association
in the design uses the VPC main route table, which the design does not
describe, so it needs review.
"""
from __future__ import annotations

from ipaddress import IPv4Network

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
ROUTE_TARGETS = frozenset("/properties/" + name for name in (
    "GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId",
    "NetworkInterfaceId", "InstanceId", "EgressOnlyInternetGatewayId",
    "LocalGatewayId", "CarrierGatewayId", "VpcEndpointId", "CoreNetworkArn"))


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
    by_id = {item.id: item for item in design.resources}
    for item in design.resources:
        if item.type not in types or item.scope != resource.scope:
            continue
        refs = [ref for ref in design.relations if ref.source_resource_id == item.id and ref.source_path == path]
        field = item.field(path)
        if (refs and len(refs) != 1) or any(
                ref.condition or ref.target_resource_id not in by_id or
                by_id[ref.target_resource_id].scope != item.scope for ref in refs) or (
                not refs and field is not None and field.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE)):
            return True
    return False


def _conditional(ctx: Context, resource, path: str) -> bool:
    return any(ref.condition for ref in ctx.design.relations
               if ref.source_resource_id == resource.id and ref.source_path == path)


def _route_target(ctx: Context, route) -> str:
    """Resolve the forwarding kind without treating uncertain links as IGWs."""
    paths = {field.path for field in route.fields if field.path in ROUTE_TARGETS
             and field.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE)}
    paths.update(ref.source_path for ref in ctx.design.relations
                 if ref.source_resource_id == route.id and ref.source_path in ROUTE_TARGETS)
    if len(paths) != 1:
        return UNKNOWN
    path = next(iter(paths))
    refs = [ref for ref in ctx.design.relations if ref.source_resource_id == route.id and ref.source_path == path]
    ctx.evidence.extend(e for ref in refs for e in ref.evidence_ids)
    field = route.field(path)
    if (field is not None and field.state not in (ValueState.KNOWN, ValueState.MISSING)) or any(ref.condition for ref in refs):
        return UNKNOWN
    if refs:
        target = ctx.by_id.get(refs[0].target_resource_id) if len(refs) == 1 else None
        if target is None or target.scope != route.scope:
            return UNKNOWN
        return PUBLIC if path == "/properties/GatewayId" and target.type == "AWS::EC2::InternetGateway" else PRIVATE
    value = ctx.value(route, path)
    if not isinstance(value, str) or not value:
        return UNKNOWN
    return PUBLIC if path == "/properties/GatewayId" and value.startswith("igw-") else PRIVATE


def _ipv4_coverage(routes: list[tuple[IPv4Network, str]]) -> str:
    """Sweep CIDR boundaries using longest prefix match, without enumerating IPs.

    Mixed forwarding may be an intentional exception, so review its intent.
    Duplicate prefixes cannot establish a valid CloudFormation route table.
    """
    boundaries = sorted({0, 2**32, *(int(n.network_address) for n, _ in routes),
                         *(int(n.broadcast_address) + 1 for n, _ in routes)})
    states = set()
    gap = False
    for start in boundaries[:-1]:
        matches = [(n.prefixlen, state) for n, state in routes
                   if int(n.network_address) <= start <= int(n.broadcast_address)]
        if not matches:
            gap = True
            continue
        longest = max(prefix for prefix, _ in matches)
        winners = [state for prefix, state in matches if prefix == longest]
        states.add(winners[0] if len(winners) == 1 else UNKNOWN)
    if UNKNOWN in states:
        return UNKNOWN
    if PUBLIC in states and PRIVATE in states:
        return UNKNOWN
    return PUBLIC if states == {PUBLIC} and not gap else PRIVATE


def subnet_reach(ctx: Context, subnet) -> tuple[str, str]:
    """Check described IPv4 fallback routes; implicit local routes are unchanged."""
    design = ctx.design
    associations = _sources(design, subnet, ("AWS::EC2::SubnetRouteTableAssociation",), "/properties/SubnetId")
    if len(associations) != 1:
        ctx.dependencies.append(f"{subnet.id} -> SubnetRouteTableAssociation")
        if not associations and not _unresolved_link(design, subnet, ("AWS::EC2::SubnetRouteTableAssociation",),
                                                     "/properties/SubnetId"):
            return UNKNOWN, f"subnet {subnet.name} uses the VPC main route table, which the design does not describe"
        return UNKNOWN, f"route table association of subnet {subnet.name} is unresolved"
    if _unresolved_link(design, subnet, ("AWS::EC2::SubnetRouteTableAssociation",), "/properties/SubnetId") or any(
            _conditional(ctx, associations[0], p) for p in ("/properties/SubnetId", "/properties/RouteTableId")):
        return UNKNOWN, f"route table association of subnet {subnet.name} is conditional"
    table = ctx.target(associations[0], "/properties/RouteTableId", "AWS::EC2::RouteTable")
    if table is None:
        return UNKNOWN, f"route table of subnet {subnet.name} is unresolved"
    unknown = _unresolved_link(design, table, ("AWS::EC2::Route",), "/properties/RouteTableId")
    routes = []
    gateways = set()
    for route in _sources(design, table, ("AWS::EC2::Route",), "/properties/RouteTableId"):
        if route.field("/properties/DestinationPrefixListId"):
            unknown = True  # Prefix-list entries/priority are not expanded here.
            continue
        if not route.field("/properties/DestinationCidrBlock") and route.field("/properties/DestinationIpv6CidrBlock"):
            continue  # IPv6 does not establish or override an IPv4 route.
        destination = ctx.value(route, "/properties/DestinationCidrBlock")
        try:
            if not isinstance(destination, str):
                raise ValueError("unknown IPv4 CIDR")
            network = IPv4Network(destination, strict=False)
        except ValueError:
            unknown = True
            continue
        target = _route_target(ctx, route)
        if target == PUBLIC:
            refs = [ref for ref in design.relations if ref.source_resource_id == route.id
                    and ref.source_path == "/properties/GatewayId"]
            gateways.add(refs[0].target_resource_id if refs else ctx.value(route, "/properties/GatewayId"))
        routes.append((network, target))
    # Multiple IGW identities need attachment/VPC reconciliation beyond this check.
    unknown = unknown or len(gateways) > 1
    reach = UNKNOWN if unknown else _ipv4_coverage(routes)
    if reach == UNKNOWN:
        ctx.dependencies.append(f"{table.id} routes")
        return UNKNOWN, f"IPv4 routes of subnet {subnet.name} are unresolved, ambiguous, or include forwarding exceptions requiring review"
    if reach == PUBLIC:
        return PUBLIC, f"subnet {subnet.name} has complete IPv4 fallback coverage through internet gateway routes"
    return PRIVATE, f"route table of subnet {subnet.name} lacks complete IPv4 fallback coverage through an internet gateway"


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
        subnet = None if _conditional(ctx, resource, path) else ctx.target(resource, path, "AWS::EC2::Subnet")
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
    subnets = [None if ref.condition else ctx.target(resource, ref.source_path, "AWS::EC2::Subnet") for ref in refs]
    if not subnets or any(subnet is None for subnet in subnets):
        return ctx.finding(rule, "/properties/Subnets", "NEEDS_REVIEW", "subnets are not all linked in the design")
    reaches = [subnet_reach(ctx, subnet) for subnet in subnets]
    failed = [reason for reach, reason in reaches if reach == PRIVATE]
    if failed:
        return ctx.finding(rule, "/properties/Subnets", "FAIL", "; ".join(failed))
    if any(reach == UNKNOWN for reach, _ in reaches):
        return ctx.finding(rule, "/properties/Subnets", "NEEDS_REVIEW",
                           "; ".join(reason for reach, reason in reaches if reach == UNKNOWN))
    return ctx.finding(rule, "/properties/Subnets", "PASS", "every subnet has complete IPv4 fallback coverage through internet gateway routes")
