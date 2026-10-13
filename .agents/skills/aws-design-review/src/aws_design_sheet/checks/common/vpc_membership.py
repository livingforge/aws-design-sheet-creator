"""VPC membership of subnets and Classic ELB subnet zones."""
import re
from .context_values import linked, value
from .field_reads import ABSENT

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLASSIC_ELB_SUBNET_ZONES': [CF + 'aws-resource-elasticloadbalancing-loadbalancer.html'],
}


def vpc_membership(ctx, resource, vpc_base, rule, *, include_security_groups=True):
    if value(ctx, resource, vpc_base) is ABSENT:
        return []
    identities, pending = set(), False
    kinds = [('Subnets', 'AWS::EC2::Subnet')]
    if include_security_groups:
        kinds.append(('SecurityGroups', 'AWS::EC2::SecurityGroup'))
    for key, kind in kinds:
        members = value(ctx, resource, vpc_base + '/' + key)
        if members is ABSENT and key == 'SecurityGroups':
            continue
        if not isinstance(members, list):
            pending = True
            continue
        for i in range(len(members)):
            member = linked(ctx, resource, vpc_base + f'/{key}/{i}', kind)
            vpc = linked(ctx, member, '/properties/VpcId', 'AWS::EC2::VPC') if member else None
            if vpc:
                identities.add(('resource', vpc.id))
            elif member:
                raw = value(ctx, member, '/properties/VpcId')
                if isinstance(raw, str) and re.fullmatch(r'vpc-[0-9a-f]+', raw):
                    identities.add(('literal', raw))
                else:
                    pending = True
            else:
                pending = True
    # Different literal and logical identities might be aliases, so compare only like forms.
    conflicting = any(len({v for kind, v in identities if kind == category}) > 1 for category in ('resource', 'literal'))
    pending |= len({kind for kind, _ in identities}) > 1 or not identities
    return [ctx.finding(rule, vpc_base,
        'FAIL' if conflicting else 'NEEDS_REVIEW' if pending else 'PASS',
        ('resolved subnets and security groups' if include_security_groups else 'resolved subnets')
        + ' must share a VPC; mixed logical/literal aliases require review')]


def classic_subnet_zones(ctx, resource, path='/properties/Subnets', rule='CLASSIC_ELB_SUBNET_ZONES', child=''):
    subnets = value(ctx, resource, path)
    if subnets is ABSENT:
        return []
    zones, ids = set(), set()
    pending, duplicate = not isinstance(subnets, list), False
    for i in range(len(subnets) if isinstance(subnets, list) else 0):
        subnet = linked(ctx, resource, path + f'/{i}' + child, 'AWS::EC2::Subnet')
        if not subnet:
            pending = True
            continue
        found = False
        for field, seen in [('AvailabilityZone', zones), ('AvailabilityZoneId', ids)]:
            zone = value(ctx, subnet, '/properties/' + field)
            if isinstance(zone, str) and '{{' not in zone:
                duplicate |= zone in seen
                seen.add(zone)
                found = True
        pending |= not found
    # A name and an AZ ID cannot be mapped without additional regional evidence.
    pending |= bool(zones and ids) and not (len(zones) == len(subnets) or len(ids) == len(subnets)) if isinstance(subnets, list) else True
    return [ctx.finding(rule, path,
        'FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS',
        'at most one linked subnet per Availability Zone; unresolved zone names or IDs require review')]
