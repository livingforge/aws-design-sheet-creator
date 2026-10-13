"""Checks for these resource types:

- AWS::ElasticLoadBalancingV2::LoadBalancer
- AWS::ElasticLoadBalancingV2::TargetGroup
- AWS::ElasticLoadBalancingV2::ListenerRule
"""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from .listener_links import alb_target_listener_port, evaluate_listener_links
from .load_balancer_subnets import load_balancer_subnets
from .matcher_codes import matcher_codes
from .target_group_attributes import target_group_attributes
from .target_group_links import target_group_links

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'ELBV2_JWT_CLAIM_SPACES': [CF + 'aws-properties-elasticloadbalancingv2-listenerrule-jwtvalidationactionadditionalclaim.html'],
    'ELBV2_ATTRIBUTE_TYPE': ['https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html', CF + 'aws-resource-elasticloadbalancingv2-loadbalancer.html'],
    'ELBV2_ALB_CROSS_ZONE': ['https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html'],
    'ELBV2_SINGLETON_CONDITIONS': ['https://docs.aws.amazon.com/elasticloadbalancing/latest/application/rule-condition-types.html'],
    'ELBV2_HOST_HEADER_VALUES': [CF + 'aws-properties-elasticloadbalancingv2-listenerrule-hostheaderconfig.html'],
    'ELBV2_FORWARD_TARGET_MATCH': [CF + 'aws-properties-elasticloadbalancingv2-listenerrule-forwardconfig.html'],
}
ALL_LB = {'application', 'network', 'gateway'}
LB_ATTRIBUTES = {
    **{key: ALL_LB for key in ('deletion_protection.enabled', 'load_balancing.cross_zone.enabled')},
    **{key: {'application', 'network'} for key in ('access_logs.s3.enabled', 'access_logs.s3.bucket',
        'access_logs.s3.prefix', 'ipv6.deny_all_igw_traffic', 'zonal_shift.config.enabled')},
    **{key: {'application'} for key in ('idle_timeout.timeout_seconds', 'client_keep_alive.seconds',
        'connection_logs.s3.enabled', 'connection_logs.s3.bucket', 'connection_logs.s3.prefix',
        'health_check_logs.s3.enabled', 'health_check_logs.s3.bucket', 'health_check_logs.s3.prefix',
        'routing.http.desync_mitigation_mode', 'routing.http.drop_invalid_header_fields.enabled',
        'routing.http.preserve_host_header.enabled', 'routing.http.x_amzn_tls_version_and_cipher_suite.enabled',
        'routing.http.xff_client_port.enabled', 'routing.http.xff_header_processing.mode',
        'routing.http2.enabled', 'waf.fail_open.enabled')},
    **{key: {'network'} for key in ('dns_record.client_routing_policy', 'secondary_ips.auto_assigned.per_subnet')},
}


@resource_check('AWS::ElasticLoadBalancingV2::LoadBalancer')
def lb_attributes(design, resource):
    ctx = _Context(design, resource)
    results = load_balancer_subnets(design, resource)
    base = '/properties/LoadBalancerAttributes'
    attrs = value(ctx, resource, base)
    if attrs is ABSENT or attrs == []:
        return results
    kind = value(ctx, resource, '/properties/Type')
    if kind is ABSENT:
        kind = 'application'  # Documented CloudFormation default.
    if not isinstance(attrs, list):
        return results + [ctx.finding('ELBV2_ATTRIBUTE_TYPE', base, 'NEEDS_REVIEW', 'attributes are unresolved')]
    for i in range(len(attrs)):
        path = base + f'/{i}'
        key = value(ctx, resource, path + '/Key')
        supported = LB_ATTRIBUTES.get(key) if isinstance(key, str) else None
        verdict = ('NEEDS_REVIEW' if supported is None or not isinstance(kind, str) or kind not in ALL_LB
                   else 'PASS' if kind in supported else 'FAIL')
        results.append(ctx.finding('ELBV2_ATTRIBUTE_TYPE', path + '/Key', verdict,
            'checks documented attribute support; unlisted future attributes require review'))
        if key == 'load_balancing.cross_zone.enabled' and kind == 'application':
            flag = value(ctx, resource, path + '/Value')
            verdict = 'PASS' if flag == 'true' else 'FAIL' if flag == 'false' else 'NEEDS_REVIEW'
            results.append(ctx.finding('ELBV2_ALB_CROSS_ZONE', path + '/Value', verdict,
                'Application Load Balancer cross-zone balancing is always enabled'))
    return results


@resource_check('AWS::ElasticLoadBalancingV2::TargetGroup')
def target_group_checks(design, resource):
    return (target_group_attributes(design, resource) + alb_target_listener_port(design, resource)
            + matcher_codes(design, resource) + target_group_links(design, resource))


@resource_check('AWS::ElasticLoadBalancingV2::ListenerRule')
def listener_local(design, resource):
    ctx = _Context(design, resource)
    results = evaluate_listener_links(design, resource)
    conditions = value(ctx, resource, '/properties/Conditions')
    if isinstance(conditions, list):
        fields = [value(ctx, resource, f'/properties/Conditions/{i}/Field') for i in range(len(conditions))]
        bad = any(fields.count(k) > 1 for k in ('host-header', 'http-request-method', 'path-pattern', 'source-ip'))
        pending = any(not isinstance(k, str) for k in fields)
        results.append(ctx.finding('ELBV2_SINGLETON_CONDITIONS', '/properties/Conditions',
            'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS', 'four singleton condition types may occur at most once'))
        for i, field in enumerate(fields):
            if field != 'host-header':
                continue
            for suffix in ('Values', 'HostHeaderConfig/Values'):
                path = f'/properties/Conditions/{i}/' + suffix
                names = value(ctx, resource, path)
                if names is ABSENT:
                    continue
                verdict = 'NEEDS_REVIEW'
                if isinstance(names, list):
                    known = [v for v in names if isinstance(v, str) and '{{' not in v]
                    bad = any(not re.fullmatch(r'.*\.[a-zA-Z]+', v) for v in known)
                    verdict = 'FAIL' if bad else 'NEEDS_REVIEW' if len(known) != len(names) else 'PASS'
                results.append(ctx.finding('ELBV2_HOST_HEADER_VALUES', path, verdict,
                    'host value patterns need a dot and an alphabetical final label; regex values are separate'))
    elif conditions is not ABSENT:
        results.append(ctx.finding('ELBV2_SINGLETON_CONDITIONS', '/properties/Conditions', 'NEEDS_REVIEW', 'conditions are unresolved'))
    actions = value(ctx, resource, '/properties/Actions')
    for i in range(len(actions) if isinstance(actions, list) else 0):
        path = f'/properties/Actions/{i}'
        results.extend(jwt_claim_spaces(ctx, resource, path))
        target = value(ctx, resource, path + '/TargetGroupArn')
        config = value(ctx, resource, path + '/ForwardConfig')
        if target is ABSENT or config is ABSENT:
            continue
        groups = value(ctx, resource, path + '/ForwardConfig/TargetGroups')
        group = value(ctx, resource, path + '/ForwardConfig/TargetGroups/0/TargetGroupArn')
        verdict = 'NEEDS_REVIEW'
        if isinstance(groups, list) and len(groups) != 1:
            verdict = 'FAIL'
        elif isinstance(target, str) and isinstance(group, str):
            verdict = 'PASS' if target == group else 'FAIL'
        results.append(ctx.finding('ELBV2_FORWARD_TARGET_MATCH', path + '/ForwardConfig', verdict,
            'when both forms are given ForwardConfig must contain the same single target group'))
    return results


def jwt_claim_spaces(ctx, resource, action):
    path = action + '/JwtValidationConfig/AdditionalClaims'
    claims = value(ctx, resource, path)
    if claims is ABSENT:
        return []
    if not isinstance(claims, list):
        return [ctx.finding('ELBV2_JWT_CLAIM_SPACES', path, 'NEEDS_REVIEW', 'claims are unresolved')]
    results = []
    for i in range(len(claims)):
        base = path + f'/{i}'
        fmt = value(ctx, resource, base + '/Format')
        if fmt in ('single-string', 'string-array'):
            continue
        values = value(ctx, resource, base + '/Values')
        verdict = 'NEEDS_REVIEW'
        if fmt == 'space-separated-values' and isinstance(values, list):
            known = [v for v in values if isinstance(v, str) and '{{' not in v]
            verdict = ('FAIL' if any(' ' in v for v in known) else
                       'NEEDS_REVIEW' if len(known) != len(values) else 'PASS')
        results.append(ctx.finding('ELBV2_JWT_CLAIM_SPACES', base + '/Values', verdict,
            'space-separated-values claim entries cannot contain spaces'))
    return results
