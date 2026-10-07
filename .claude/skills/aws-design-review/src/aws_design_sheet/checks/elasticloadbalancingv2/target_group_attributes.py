"""Relationships between explicitly declared ELBv2 target-group attributes."""
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN

URL = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-elasticloadbalancingv2-targetgroup-targetgroupattribute.html'
SOURCES = {rule:[URL] for rule in ('ELBV2_ANOMALY_WEIGHTED_RANDOM', 'ELBV2_UNHEALTHY_DRAINING_FLAG', 'ELBV2_FAILOVER_ATTRIBUTES_MATCH')}


def target_group_attributes(design, resource):
    ctx = _Context(design, resource)
    root = '/properties/TargetGroupAttributes'
    items = value(ctx, resource, root)
    if items is ABSENT:
        return []
    attributes, unknown_keys = {}, not isinstance(items, list)
    for i in range(len(items) if isinstance(items, list) else 0):
        base = root + f'/{i}'
        key = value(ctx, resource, base + '/Key')
        if not isinstance(key, str) or '{{' in key:
            unknown_keys = True
        else:
            attributes.setdefault(key, []).append(value(ctx, resource, base + '/Value'))

    def attr(key):
        values = attributes.get(key, [])
        if unknown_keys or len(values) > 1:
            return UNKNOWN
        if not values:
            return ABSENT
        raw = values[0]
        return UNKNOWN if raw is ABSENT or isinstance(raw, str) and '{{' in raw else raw

    results = []
    anomaly = attr('load_balancing.algorithm.anomaly_mitigation')
    if anomaly is not ABSENT:
        algorithm = attr('load_balancing.algorithm.type')
        verdict = 'NEEDS_REVIEW'
        if anomaly == 'off' or anomaly == 'on' and algorithm == 'weighted_random':
            verdict = 'PASS'
        elif anomaly == 'on' and algorithm in ('round_robin','least_outstanding_requests'):
            verdict = 'FAIL'
        results.append(ctx.finding('ELBV2_ANOMALY_WEIGHTED_RANDOM', root, verdict,
            'enabled anomaly mitigation requires weighted_random; omitted, duplicate or dynamic attributes are not resolved'))
    interval = attr('target_health_state.unhealthy.draining_interval_seconds')
    if interval is not ABSENT:
        flag = attr('target_health_state.unhealthy.connection_termination.enabled')
        verdict = 'NEEDS_REVIEW'
        if isinstance(interval, str) and flag in ('true','false'):
            verdict = 'PASS' if flag == 'false' else 'FAIL'
        results.append(ctx.finding('ELBV2_UNHEALTHY_DRAINING_FLAG', root, verdict,
            'an explicit unhealthy draining interval requires connection termination disabled'))
    deregistration = attr('target_failover.on_deregistration')
    unhealthy = attr('target_failover.on_unhealthy')
    if deregistration is not ABSENT or unhealthy is not ABSENT:
        known = all(v in ('rebalance','no_rebalance') for v in (deregistration,unhealthy))
        verdict = ('PASS' if deregistration == unhealthy else 'FAIL') if known else 'NEEDS_REVIEW'
        results.append(ctx.finding('ELBV2_FAILOVER_ATTRIBUTES_MATCH', root, verdict,
            'both explicit target failover values must match; omitted values are not assumed to describe existing attributes'))
    return results
