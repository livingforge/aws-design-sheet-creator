"""Checks for AWS::ElasticLoadBalancingV2::ListenerRule, AWS::ElasticLoadBalancingV2::LoadBalancer."""
from __future__ import annotations

from ..registry import resource_check
from ..common.design_uniqueness import _Context
from ..common.field_reads import ABSENT, UNKNOWN, linked, read


SOURCES = {
    "ELBV2_LOG_BUCKET_REQUIRED": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-elasticloadbalancingv2-loadbalancer-loadbalancerattribute.html"],
    "ELBV2_RULE_TERMINAL_ACTION": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancingv2-listenerrule.html",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-elasticloadbalancingv2-listenerrule-action.html"],
    "ELBV2_RULE_AUTH_HTTPS": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-elasticloadbalancingv2-listenerrule-action.html"],
    "ELBV2_RULE_REDIRECT_NO_DOWNGRADE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-elasticloadbalancingv2-listenerrule-redirectconfig.html"],
}


@resource_check('AWS::ElasticLoadBalancingV2::ListenerRule')
def listener_actions(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/Actions'
    actions = read(ctx, resource, path)
    if not isinstance(actions, list):
        return [ctx.finding('ELBV2_RULE_TERMINAL_ACTION', path, 'NEEDS_REVIEW', 'actions are unresolved')]
    kinds = [read(ctx, resource, path + f'/{i}/Type') for i in range(len(actions))]
    terminal = [i for i, kind in enumerate(kinds) if kind in ('forward', 'redirect', 'fixed-response')]
    unknown = any(not isinstance(kind, str) for kind in kinds)
    orders = [read(ctx, resource, path + f'/{i}/Order') for i in range(len(actions))]
    if len(terminal) > 1 or (not terminal and not unknown):
        verdict = 'FAIL'
    elif unknown or any(type(v) is not int for v in orders) and len(actions) > 1:
        verdict = 'NEEDS_REVIEW'
    elif len(actions) == 1:
        verdict = 'PASS'
    elif len(set(orders)) != len(orders):
        verdict = 'FAIL'
    else:
        verdict = 'PASS' if orders[terminal[0]] == max(orders) else 'FAIL'
    results = [ctx.finding('ELBV2_RULE_TERMINAL_ACTION', path, verdict,
                           'exactly one routing action is required and must execute last by Order')]
    listener = linked(ctx, resource, '/properties/ListenerArn', 'AWS::ElasticLoadBalancingV2::Listener')
    protocol = read(ctx, listener, '/properties/Protocol') if listener else UNKNOWN
    for i, kind in enumerate(kinds):
        if kind in ('authenticate-cognito', 'authenticate-oidc', 'jwt-validation'):
            verdict = 'NEEDS_REVIEW' if not isinstance(protocol, str) else 'PASS' if protocol == 'HTTPS' else 'FAIL'
            results.append(ctx.finding('ELBV2_RULE_AUTH_HTTPS', path + f'/{i}', verdict,
                                      'authentication and JWT validation require an HTTPS listener'))
        if kind == 'redirect':
            redirect = read(ctx, resource, path + f'/{i}/RedirectConfig/Protocol')
            if redirect == 'HTTP':
                verdict = 'NEEDS_REVIEW' if not isinstance(protocol, str) else 'FAIL' if protocol == 'HTTPS' else 'PASS'
                results.append(ctx.finding('ELBV2_RULE_REDIRECT_NO_DOWNGRADE', path + f'/{i}', verdict,
                                          'an HTTPS listener cannot redirect to HTTP'))
    return results


@resource_check('AWS::ElasticLoadBalancingV2::LoadBalancer')
def load_balancer_log_buckets(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/LoadBalancerAttributes'
    items = read(ctx, resource, path)
    if items is ABSENT:
        return []
    if not isinstance(items, list):
        return [ctx.finding('ELBV2_LOG_BUCKET_REQUIRED', path, 'NEEDS_REVIEW', 'attributes are unresolved')]
    attributes = {}
    pending_keys = False
    for i in range(len(items)):
        key = read(ctx, resource, path + f'/{i}/Key')
        value = read(ctx, resource, path + f'/{i}/Value')
        if isinstance(key, str):
            attributes.setdefault(key, []).append(value)
        else:
            pending_keys = True
    results = []
    for log in ('access_logs', 'connection_logs', 'health_check_logs'):
        enabled = attributes.get(log + '.s3.enabled', [])
        buckets = attributes.get(log + '.s3.bucket', [])
        if enabled == ['false'] or not enabled and not pending_keys:
            continue
        if enabled != ['true']:
            verdict = 'NEEDS_REVIEW'
        elif not buckets:
            verdict = 'NEEDS_REVIEW' if pending_keys else 'FAIL'
        elif len(buckets) != 1 or not isinstance(buckets[0], str):
            verdict = 'NEEDS_REVIEW'
        else:
            verdict = 'PASS' if buckets[0] else 'FAIL'
        results.append(ctx.finding('ELBV2_LOG_BUCKET_REQUIRED', path, verdict,
                                  log + ' requires a nonempty S3 bucket attribute when enabled'))
    return results
