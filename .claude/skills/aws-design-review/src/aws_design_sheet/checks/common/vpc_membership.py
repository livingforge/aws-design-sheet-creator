"""VPC membership of subnets and Classic ELB subnet zones."""
import re
from .context_values import linked, value
from .field_reads import ABSENT
from .index import relations_from

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLASSIC_ELB_SUBNET_ZONES': [CF + 'aws-resource-elasticloadbalancing-loadbalancer.html'],
}


def _paths_below(ctx, resource, base):
    """Source paths of the resource's relations below base, relative to it."""
    prefix = base + '/'
    return [r.source_path[len(prefix):] for r in relations_from(ctx.design, resource.id)
            if r.source_path.startswith(prefix)]


def _linked_indices(ctx, resource, base):
    """Sorted list indices under base that hold a relation (base/<n> or deeper)."""
    return sorted({int(head) for head in (p.split('/', 1)[0] for p in _paths_below(ctx, resource, base))
                   if head.isdigit()})


def vpc_membership(ctx, resource, vpc_base, rule, *, include_security_groups=True,
                   subnet_key='Subnets', security_group_key='SecurityGroups', finding_path=None,
                   subnet_child=''):
    """Subnets and security groups listed under vpc_base must resolve to one VPC.

    vpc_base may be '/properties' for types that list them at the top level; the
    key names default to the Subnets/SecurityGroups of a VpcConfiguration object.
    subnet_child names the subnet inside each list item, such as '/SubnetId' of SubnetMappings.
    """
    if value(ctx, resource, vpc_base) is ABSENT and not _paths_below(ctx, resource, vpc_base):
        return []
    identities, pending = set(), False
    kinds = [(subnet_key, 'AWS::EC2::Subnet', subnet_child)]
    if include_security_groups:
        kinds.append((security_group_key, 'AWS::EC2::SecurityGroup', ''))
    for key, kind, child in kinds:
        members = value(ctx, resource, vpc_base + '/' + key)
        if members is ABSENT:
            # A list made only of references is held as relations, one per item, without a field.
            indices = _linked_indices(ctx, resource, vpc_base + '/' + key)
            if indices:
                members = indices if indices == list(range(len(indices))) else None
            elif key == security_group_key:
                continue
        if not isinstance(members, list):
            pending = True
            continue
        for i in range(len(members)):
            member = linked(ctx, resource, vpc_base + f'/{key}/{i}' + child, kind)
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
    return [ctx.finding(rule, finding_path or vpc_base,
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
