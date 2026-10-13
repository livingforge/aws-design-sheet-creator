"""Detect explicit Internet Gateway routes from EKS Fargate subnets."""
import re
from ...template_dependencies import explicit_dependencies, members
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from .links import cluster_identity

SOURCES = {'EKS_FARGATE_PRIVATE_SUBNET': [
    'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-fargateprofile.html']}
SOURCES['EKS_FARGATE_IDP_ORDER'] = SOURCES['EKS_FARGATE_PRIVATE_SUBNET']


def identity(ctx, resource, path, kind, prefix):
    target = linked(ctx, resource, path, kind)
    if target:
        return ('resource', target.id)
    raw = value(ctx, resource, path)
    if isinstance(raw, str) and re.fullmatch(prefix + r'-[0-9a-f]+', raw):
        return ('literal', raw)
    return None


@resource_check('AWS::EKS::FargateProfile')
def fargate_private_subnets(design, resource):
    ctx = _Context(design, resource)
    results = fargate_idp_order(ctx, resource)
    subnets = value(ctx, resource, '/properties/Subnets')
    if subnets is ABSENT:
        return results
    if not isinstance(subnets, list):
        return results + [ctx.finding('EKS_FARGATE_PRIVATE_SUBNET', '/properties/Subnets', 'NEEDS_REVIEW', 'subnet list is unresolved')]
    candidates = [r for r in design.resources if r.scope == resource.scope]
    for i in range(len(subnets)):
        path = f'/properties/Subnets/{i}'
        subnet = identity(ctx, resource, path, 'AWS::EC2::Subnet', 'subnet')
        tables = []
        if subnet:
            for association in candidates:
                if association.type != 'AWS::EC2::SubnetRouteTableAssociation':
                    continue
                if identity(ctx, association, '/properties/SubnetId', 'AWS::EC2::Subnet', 'subnet') == subnet:
                    tables.append(identity(ctx, association, '/properties/RouteTableId', 'AWS::EC2::RouteTable', 'rtb'))
        public_routes = []
        if len(tables) == 1 and tables[0]:
            for route in candidates:
                if route.type != 'AWS::EC2::Route':
                    continue
                table = identity(ctx, route, '/properties/RouteTableId', 'AWS::EC2::RouteTable', 'rtb')
                if table != tables[0]:
                    continue
                gateway = identity(ctx, route, '/properties/GatewayId', 'AWS::EC2::InternetGateway', 'igw')
                if gateway:
                    public_routes.append(route.id)
        results.append(ctx.finding('EKS_FARGATE_PRIVATE_SUBNET', path,
            'FAIL' if public_routes else 'NEEDS_REVIEW',
            'Fargate subnet has explicit direct Internet Gateway routes: ' + ', '.join(public_routes)
            if public_routes else 'no proven direct Internet Gateway route; main/external tables, missing associations and unknown routes remain unverified'))
    return results


def fargate_idp_order(ctx, resource):
    cluster = cluster_identity(ctx, resource)
    pool = members(ctx.design, resource)
    targets, uncertain = [], False
    for other in ctx.design.resources:
        if other.type != 'AWS::EKS::IdentityProviderConfig' or other.scope != resource.scope:
            continue
        other_cluster = cluster_identity(ctx, other)
        if cluster and other_cluster and cluster != other_cluster:
            if cluster[0] != other_cluster[0]:
                uncertain = True  # A logical reference may be an alias for the literal name.
            continue
        if not cluster or not other_cluster:
            uncertain = True
            continue
        if other in pool:
            targets.append(other)
        elif not pool or not other.template or other.template.state.value != 'KNOWN':
            uncertain = True
    if not targets and not uncertain:
        return []
    reached, graph_unknown, invalid = explicit_dependencies(ctx, resource)
    missing = []
    for other in targets:
        other_ctx = _Context(ctx.design, other)
        reverse, reverse_unknown, reverse_invalid = explicit_dependencies(other_ctx, other)
        ctx.evidence.extend(other_ctx.evidence)
        ctx.dependencies.extend(other_ctx.dependencies)
        invalid |= reverse_invalid
        if other.id not in reached and resource.id not in reverse:
            missing.append(other.id)
            uncertain |= graph_unknown or reverse_unknown
    verdict = 'FAIL' if invalid else 'NEEDS_REVIEW' if uncertain else 'FAIL' if missing else 'PASS'
    return [ctx.finding('EKS_FARGATE_IDP_ORDER', '/template/depends_on', verdict,
        'Fargate profile and identity-provider creation for the same cluster/template must be ordered; either dependency direction prevents concurrency, unknown membership or incomplete graphs require review')]
