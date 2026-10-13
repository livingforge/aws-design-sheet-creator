"""Proven forwarding paths from target groups to declared load balancers."""
import re
import ipaddress
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT

PREFIX = 'AWS::ElasticLoadBalancingV2::'
SOURCES = {
    'ELBV2_ALB_MATCHER_RANGE': ['https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_Matcher.html'],
    'ELBV2_ALB_IPV6_TARGET': ['https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html'],
    'ELBV2_TARGET_ADDRESS_FAMILY': ['https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html'],
}


def forwarding_balancers(ctx, group):
    """Return only exact unconditional, same-scope forwarding chains."""
    found = {}
    for owner in ctx.design.resources:
        if owner.type not in (PREFIX + 'Listener', PREFIX + 'ListenerRule'):
            continue
        base = '/properties/' + ('DefaultActions' if owner.type == PREFIX + 'Listener' else 'Actions')
        actions = value(ctx, owner, base)
        if not isinstance(actions, list):
            continue
        matches = False
        for i in range(len(actions)):
            path = base + '/' + str(i)
            if value(ctx, owner, path + '/Type') != 'forward':
                continue
            paths = [path + '/TargetGroupArn']
            weighted = value(ctx, owner, path + '/ForwardConfig/TargetGroups')
            if isinstance(weighted, list):
                paths.extend(path + '/ForwardConfig/TargetGroups/' + str(j) + '/TargetGroupArn'
                             for j in range(len(weighted)))
            for target_path in paths:
                target = linked(ctx, owner, target_path, PREFIX + 'TargetGroup')
                matches |= target is not None and target.id == group.id
        if not matches:
            continue
        listener = owner if owner.type == PREFIX + 'Listener' else linked(ctx, owner, '/properties/ListenerArn', PREFIX + 'Listener')
        lb = linked(ctx, listener, '/properties/LoadBalancerArn', PREFIX + 'LoadBalancer') if listener else None
        if lb:
            found[lb.id] = lb
    return list(found.values())


def target_group_links(design, resource):
    ctx = _Context(design, resource)
    http_path = '/properties/Matcher/HttpCode'
    raw = value(ctx, resource, http_path)
    family = value(ctx, resource, '/properties/IpAddressType')
    target_type = value(ctx, resource, '/properties/TargetType')
    if raw is ABSENT and family != 'ipv6' and target_type != 'ip':
        return []
    balancers = forwarding_balancers(ctx, resource)
    applications = [lb for lb in balancers if value(ctx, lb, '/properties/Type') in (ABSENT, 'application')]
    results = []
    if raw is not ABSENT:
        verdict = 'NEEDS_REVIEW'
        if applications and isinstance(raw, str) and len(raw) <= 4096 and re.fullmatch(
                r'[0-9]{1,4}(?:-[0-9]{1,4})?(?:,[0-9]{1,4}(?:-[0-9]{1,4})?)*', raw):
            pairs = [list(map(int, part.split('-'))) for part in raw.split(',')]
            verdict = 'PASS' if all(200 <= pair[0] <= pair[-1] <= 499 for pair in pairs) else 'FAIL'
        results.append(ctx.finding('ELBV2_ALB_MATCHER_RANGE', http_path, verdict,
            'checks HTTP 200..499 only for a proven Listener/ListenerRule forward chain to an application load balancer; unresolved references, protocol applicability and other load-balancer types remain unverified'))
    if family == 'ipv6':
        verdict = 'NEEDS_REVIEW'
        if applications:
            families = [value(ctx, lb, '/properties/IpAddressType') for lb in applications]
            # Only explicit address types; omitted defaults and unknown variants are not inferred.
            verdict = ('FAIL' if 'ipv4' in families else 'PASS'
                       if all(f in ('dualstack', 'dualstack-without-public-ipv4') for f in families) else 'NEEDS_REVIEW')
        results.append(ctx.finding('ELBV2_ALB_IPV6_TARGET', '/properties/IpAddressType', verdict,
            'an IPv6 target group cannot use a proven IPv4 application load balancer; checks explicit address types only, not target reachability or external associations'))
    if target_type == 'ip':
        targets = value(ctx, resource, '/properties/Targets')
        for i in range(len(targets) if isinstance(targets, list) else 0):
            path = '/properties/Targets/' + str(i) + '/Id'
            address = value(ctx, resource, path)
            verdict = 'NEEDS_REVIEW'
            if applications and family in ('ipv4', 'ipv6') and isinstance(address, str) and '%' not in address:
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    pass
                else:
                    verdict = 'PASS' if family == 'ipv' + str(parsed.version) else 'FAIL'
            results.append(ctx.finding('ELBV2_TARGET_ADDRESS_FAMILY', path, verdict,
                'checks literal IP target version against an explicit application target-group address type; subnet eligibility, public routability, AvailabilityZone and reachability remain unverified'))
    return results
