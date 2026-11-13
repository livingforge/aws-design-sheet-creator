"""VPC membership and IPv6 of a load balancer's subnets.

Elastic Load Balancing refuses subnets from more than one VPC ("All subnets must belong to the
same VPC") and security groups of another VPC, and a dualstack load balancer on a subnet without
an IPv6 CIDR block ("You must specify subnets with an associated IPv6 CIDR block."); cfn-lint
1.57.2 reports none of these.
"""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.index import relations_from
from ..common.vpc_membership import vpc_membership

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'ELBV2_LOAD_BALANCER_VPC_MEMBERSHIP': [
        CF + 'aws-resource-elasticloadbalancingv2-loadbalancer.html',
        'https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_SetSubnets.html'],
    'ELBV2_DUALSTACK_SUBNET_IPV6': [
        CF + 'aws-resource-elasticloadbalancingv2-loadbalancer.html',
        'https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_SetIpAddressType.html'],
}


def _listed(ctx, resource, key):
    return (value(ctx, resource, '/properties/' + key) is not ABSENT
            or any(r.source_path.startswith(f'/properties/{key}/') for r in relations_from(ctx.design, resource.id)))


@resource_check('AWS::ElasticLoadBalancingV2::LoadBalancer')
def evaluate_load_balancer_vpc_membership(design, resource):
    ctx = _Context(design, resource)
    if _listed(ctx, resource, 'Subnets'):
        key, child = 'Subnets', ''
    elif _listed(ctx, resource, 'SubnetMappings'):
        key, child = 'SubnetMappings', '/SubnetId'
    else:
        return []
    return vpc_membership(ctx, resource, '/properties', 'ELBV2_LOAD_BALANCER_VPC_MEMBERSHIP',
                          subnet_key=key, subnet_child=child, finding_path='/properties/' + key)


def _subnet_has_ipv6(design, ctx, subnet):
    """True when the subnet declares an IPv6 block (even an unresolved one) or is IPv6-only."""
    if value(ctx, subnet, '/properties/Ipv6CidrBlock') is not ABSENT or value(ctx, subnet, '/properties/Ipv6Native') in (True, 'true'):
        return True
    if any(r.source_path.startswith('/properties/Ipv6CidrBlock') for r in relations_from(design, subnet.id)):
        return True
    for other in design.resources:
        if other.type == 'AWS::EC2::SubnetCidrBlock' and any(
                r.source_path == '/properties/SubnetId' and r.target_resource_id == subnet.id
                for r in relations_from(design, other.id)):
            local = _Context(design, other)
            if any(value(local, other, '/properties/' + key) is not ABSENT for key in ('Ipv6CidrBlock', 'Ipv6IpamPoolId')):
                return True
    return False


@resource_check('AWS::ElasticLoadBalancingV2::LoadBalancer')
def evaluate_dualstack_subnet_ipv6(design, resource):
    ctx = _Context(design, resource)
    if value(ctx, resource, '/properties/IpAddressType') not in ('dualstack', 'dualstack-without-public-ipv4'):
        return []
    if _listed(ctx, resource, 'Subnets'):
        key, child = 'Subnets', ''
    elif _listed(ctx, resource, 'SubnetMappings'):
        key, child = 'SubnetMappings', '/SubnetId'
    else:
        return []
    links = sorted({int(r.source_path.split('/')[3]) for r in relations_from(design, resource.id)
                    if r.source_path.startswith(f'/properties/{key}/') and r.source_path.split('/')[3].isdigit()})
    listed = value(ctx, resource, '/properties/' + key)
    count = len(listed) if isinstance(listed, list) else len(links)
    results = []
    for i in range(count):
        path = f'/properties/{key}/{i}{child}'
        local = _Context(design, resource)
        subnet = linked(local, resource, path, 'AWS::EC2::Subnet')
        if subnet is None:
            verdict, reason = 'NEEDS_REVIEW', 'the subnet is not declared in the design'
        elif _subnet_has_ipv6(design, local, subnet):
            verdict, reason = 'PASS', 'the subnet has an IPv6 CIDR block'
        else:
            verdict, reason = 'FAIL', 'a dualstack load balancer needs subnets with an IPv6 CIDR block'
        results.append(local.finding('ELBV2_DUALSTACK_SUBNET_IPV6', path, verdict, reason))
    return results
