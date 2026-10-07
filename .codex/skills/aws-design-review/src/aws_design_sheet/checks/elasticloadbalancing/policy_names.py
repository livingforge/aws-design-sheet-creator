"""Checks for AWS::ElasticLoadBalancing::LoadBalancer."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.vpc_membership import classic_subnet_zones

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CLASSIC_ELB_POLICY_NAMES': [CF + 'aws-properties-elasticloadbalancing-loadbalancer-appcookiestickinesspolicy.html', CF + 'aws-properties-elasticloadbalancing-loadbalancer-lbcookiestickinesspolicy.html'],
}


@resource_check('AWS::ElasticLoadBalancing::LoadBalancer')
def classic_policy_names(design, resource):
    ctx = _Context(design, resource)
    seen, duplicate, pending, present = set(), False, False, False
    for collection in ('AppCookieStickinessPolicy', 'LBCookieStickinessPolicy', 'Policies'):
        path = '/properties/' + collection
        items = value(ctx, resource, path)
        if items is ABSENT:
            continue
        present = True
        if not isinstance(items, list):
            pending = True
            continue
        for i in range(len(items)):
            name = value(ctx, resource, path + f'/{i}/PolicyName')
            if not isinstance(name, str) or '{{' in name:
                pending = True
            else:
                duplicate |= name in seen
                seen.add(name)
    results = [ctx.finding('CLASSIC_ELB_POLICY_NAMES', '/properties',
        'FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS',
        'policy names must be unique across all three policy collections on this load balancer')] if present else []
    results.extend(classic_subnet_zones(ctx, resource))
    return results
