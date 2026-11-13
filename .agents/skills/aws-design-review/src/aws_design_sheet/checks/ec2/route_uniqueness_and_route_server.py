"""Client VPN routes declared twice and route server endpoints outside the associated VPC.

cfn-lint 1.57.2 compares neither; AWS refused both in aws-emulator-evaluation-suite:

- a second Client VPN route with the same destination CIDR and target subnet on one endpoint
  (InvalidClientVpnDuplicateRoute, "Route already exists");
- a route server endpoint in a subnet of a VPC the route server is not associated with
  (InvalidParameterValue).
"""
import ipaddress
import re

from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
API = 'https://docs.aws.amazon.com/AWSEC2/latest/APIReference/'
SOURCES = {
    'EC2_CLIENT_VPN_ROUTE_DUPLICATE': [CF + 'aws-resource-ec2-clientvpnroute.html', API + 'API_CreateClientVpnRoute.html'],
    'EC2_ROUTE_SERVER_ENDPOINT_VPC': [CF + 'aws-resource-ec2-routeserverendpoint.html',
                                      CF + 'aws-resource-ec2-routeserverassociation.html',
                                      API + 'API_CreateRouteServerEndpoint.html'],
}


def _identity(ctx, resource, path, kind, pattern):
    target = linked(ctx, resource, path, kind)
    if target is not None:
        return ('resource', target.id)
    raw = value(ctx, resource, path)
    return ('literal', raw) if isinstance(raw, str) and re.fullmatch(pattern, raw) else None


def _route_key(ctx, resource):
    endpoint = _identity(ctx, resource, '/properties/ClientVpnEndpointId', 'AWS::EC2::ClientVpnEndpoint', r'cvpn-endpoint-[0-9a-f]+')
    subnet = _identity(ctx, resource, '/properties/TargetVpcSubnetId', 'AWS::EC2::Subnet', r'subnet-[0-9a-f]+')
    destination = value(ctx, resource, '/properties/DestinationCidrBlock')
    try:
        network = str(ipaddress.ip_network(destination, strict=False)) if literal(destination) else None
    except ValueError:
        network = None
    return (endpoint, subnet, network) if endpoint and subnet and network else None


@resource_check('AWS::EC2::ClientVpnRoute')
def evaluate_client_vpn_route_duplicate(design, resource):
    ctx = _Context(design, resource)
    key = _route_key(ctx, resource)
    if key is None:
        return []
    others = sorted(other.name for other in design.resources
                    if other.id != resource.id and other.type == resource.type
                    and _route_key(_Context(design, other), other) == key)
    if others:
        return [ctx.finding('EC2_CLIENT_VPN_ROUTE_DUPLICATE', '/properties/DestinationCidrBlock', 'FAIL',
                            f'route to {key[2]} through the same subnet is also declared by ' + ', '.join(others))]
    return [ctx.finding('EC2_CLIENT_VPN_ROUTE_DUPLICATE', '/properties/DestinationCidrBlock', 'PASS',
                        'no other route in the design has this endpoint, destination and subnet')]


def _vpc_of(ctx, owner, path, kind):
    """Identity of the VPC at owner/path (a subnet's VpcId when kind is a subnet)."""
    if kind == 'AWS::EC2::Subnet':
        subnet = linked(ctx, owner, path, kind)
        if subnet is None:
            return None
        owner, path = subnet, '/properties/VpcId'
    return _identity(ctx, owner, path, 'AWS::EC2::VPC', r'vpc-[0-9a-f]+')


@resource_check('AWS::EC2::RouteServerEndpoint')
def evaluate_route_server_endpoint_vpc(design, resource):
    ctx = _Context(design, resource)
    server = linked(ctx, resource, '/properties/RouteServerId', 'AWS::EC2::RouteServer')
    if server is None:
        return []
    associations = []
    for other in design.resources:
        if other.type == 'AWS::EC2::RouteServerAssociation':
            local = _Context(design, other)
            if linked(local, other, '/properties/RouteServerId', 'AWS::EC2::RouteServer') is server:
                associations.append(_vpc_of(local, other, '/properties/VpcId', 'AWS::EC2::VPC'))
    if not associations:
        return []  # the association is outside the design
    vpc = _vpc_of(ctx, resource, '/properties/SubnetId', 'AWS::EC2::Subnet')
    known = [a for a in associations if a is not None]
    # A logical VPC and a literal vpc- ID might be the same VPC, so only like forms are compared.
    mixed = vpc is not None and any(kind != vpc[0] for kind, _ in known)
    if vpc is None or len(known) < len(associations) or mixed:
        verdict, reason = 'NEEDS_REVIEW', "the endpoint subnet's VPC or the route server's associated VPC is unresolved"
    elif vpc in known:
        verdict, reason = 'PASS', 'the endpoint subnet is in the VPC associated with the route server'
    else:
        verdict, reason = 'FAIL', 'the endpoint subnet is not in the VPC associated with the route server'
    return [ctx.finding('EC2_ROUTE_SERVER_ENDPOINT_VPC', '/properties/SubnetId', verdict, reason)]
