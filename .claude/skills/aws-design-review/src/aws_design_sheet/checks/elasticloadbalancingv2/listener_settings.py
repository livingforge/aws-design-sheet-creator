"""Listener default actions and listener ports that Elastic Load Balancing refuses.

cfn-lint 1.57.2 reports none of these; each was refused by AWS in aws-emulator-evaluation-suite:

- an HTTPS listener's default redirect to HTTP ("You cannot redirect HTTPS to HTTP.");
- an Application Load Balancer listener forwarding to a target group of a network protocol such
  as TCP (IncompatibleProtocols);
- a second listener on the same load balancer and port (DuplicateListener, "A listener already
  exists on this port for this load balancer");
- tcp.idle_timeout.seconds outside 60-6000 ("'tcp.idle_timeout.seconds' value '6001' must be
  between '60-6000' inclusive");
- a listener rule path-pattern value over 128 characters ("Condition value for 'path-pattern'
  cannot contain more than 128 characters").
"""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT

PREFIX = 'AWS::ElasticLoadBalancingV2::'
CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
ALB = 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/'
SOURCES = {
    'ELBV2_LISTENER_REDIRECT_NO_DOWNGRADE': [
        CF + 'aws-properties-elasticloadbalancingv2-listener-redirectconfig.html', ALB + 'load-balancer-listeners.html'],
    'ELBV2_ALB_FORWARD_PROTOCOL': [ALB + 'load-balancer-target-groups.html', ALB + 'load-balancer-listeners.html'],
    'ELBV2_LISTENER_PORT_DUPLICATE': [
        CF + 'aws-resource-elasticloadbalancingv2-listener.html',
        'https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html'],
    'ELBV2_TCP_IDLE_TIMEOUT_RANGE': [CF + 'aws-properties-elasticloadbalancingv2-listener-listenerattribute.html',
                                     'https://docs.aws.amazon.com/elasticloadbalancing/latest/network/update-idle-timeout.html'],
    'ELBV2_RULE_PATH_PATTERN_LENGTH': [CF + 'aws-properties-elasticloadbalancingv2-listenerrule-pathpatternconfig.html',
                                       ALB + 'rule-condition-types.html'],
}
NETWORK_PROTOCOLS = ('TCP', 'TLS', 'UDP', 'TCP_UDP', 'QUIC', 'TCP_QUIC', 'GENEVE')


def _forward_paths(ctx, resource, base):
    """TargetGroupArn paths of one forward action."""
    paths = []
    if value(ctx, resource, base + '/TargetGroupArn') is not ABSENT:
        paths.append(base + '/TargetGroupArn')
    groups = value(ctx, resource, base + '/ForwardConfig/TargetGroups')
    if isinstance(groups, list):
        paths.extend(f'{base}/ForwardConfig/TargetGroups/{j}/TargetGroupArn' for j in range(len(groups)))
    return paths


def _port(raw):
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    return int(raw) if isinstance(raw, str) and raw.isdigit() else None


@resource_check(PREFIX + 'Listener')
def evaluate_listener_settings(design, resource):
    ctx = _Context(design, resource)
    protocol = value(ctx, resource, '/properties/Protocol')
    results = []
    path = '/properties/DefaultActions'
    actions = value(ctx, resource, path)
    for i in range(len(actions) if isinstance(actions, list) else 0):
        base = f'{path}/{i}'
        kind = value(ctx, resource, base + '/Type')
        if kind == 'redirect' and value(ctx, resource, base + '/RedirectConfig/Protocol') == 'HTTP':
            verdict = 'NEEDS_REVIEW' if not isinstance(protocol, str) else 'FAIL' if protocol == 'HTTPS' else 'PASS'
            results.append(_Context(design, resource).finding(
                'ELBV2_LISTENER_REDIRECT_NO_DOWNGRADE', base + '/RedirectConfig/Protocol', verdict,
                'an HTTPS listener cannot redirect to HTTP'))
        if kind == 'forward' and protocol in ('HTTP', 'HTTPS'):
            for target_path in _forward_paths(ctx, resource, base):
                local = _Context(design, resource)
                group = linked(local, resource, target_path, PREFIX + 'TargetGroup')
                if group is None:
                    continue  # a literal or external target group is not checked
                target_type = value(local, group, '/properties/TargetType')
                group_protocol = value(local, group, '/properties/Protocol')
                if target_type == 'lambda' or group_protocol in ('HTTP', 'HTTPS'):
                    verdict = 'PASS'
                elif group_protocol in NETWORK_PROTOCOLS:
                    verdict = 'FAIL'
                else:
                    verdict = 'NEEDS_REVIEW'
                results.append(local.finding(
                    'ELBV2_ALB_FORWARD_PROTOCOL', target_path, verdict,
                    f'an {protocol} listener forwards only to HTTP, HTTPS or Lambda target groups, not to {group_protocol if isinstance(group_protocol, str) else "an unresolved protocol"}'))
    results.extend(_port_duplicate(design, resource))
    results.extend(_idle_timeout(design, resource))
    return results


def _listener_key(ctx, resource):
    balancer = linked(ctx, resource, '/properties/LoadBalancerArn', PREFIX + 'LoadBalancer')
    port = _port(value(ctx, resource, '/properties/Port'))
    return (balancer.id, port) if balancer is not None and port is not None else None


def _port_duplicate(design, resource):
    ctx = _Context(design, resource)
    key = _listener_key(ctx, resource)
    if key is None:
        return []
    others = [other.name for other in design.resources
              if other.id != resource.id and other.type == PREFIX + 'Listener'
              and _listener_key(_Context(design, other), other) == key]
    if others:
        return [ctx.finding('ELBV2_LISTENER_PORT_DUPLICATE', '/properties/Port', 'FAIL',
                            f'port {key[1]} of the load balancer is also used by listener ' + ', '.join(sorted(others)))]
    return [ctx.finding('ELBV2_LISTENER_PORT_DUPLICATE', '/properties/Port', 'PASS',
                        'no other listener in the design uses this load balancer port')]


def _idle_timeout(design, resource):
    ctx = _Context(design, resource)
    items = value(ctx, resource, '/properties/ListenerAttributes')
    results = []
    for i in range(len(items) if isinstance(items, list) else 0):
        base = f'/properties/ListenerAttributes/{i}'
        if value(ctx, resource, base + '/Key') != 'tcp.idle_timeout.seconds':
            continue
        local = _Context(design, resource)
        seconds = _port(value(local, resource, base + '/Value'))
        verdict = 'NEEDS_REVIEW' if seconds is None else 'PASS' if 60 <= seconds <= 6000 else 'FAIL'
        results.append(local.finding('ELBV2_TCP_IDLE_TIMEOUT_RANGE', base + '/Value', verdict,
                                     'tcp.idle_timeout.seconds is between 60 and 6000'))
    return results


@resource_check(PREFIX + 'ListenerRule')
def evaluate_rule_path_pattern_length(design, resource):
    ctx = _Context(design, resource)
    conditions = value(ctx, resource, '/properties/Conditions')
    results = []
    for i in range(len(conditions) if isinstance(conditions, list) else 0):
        base = f'/properties/Conditions/{i}'
        keys = ['/PathPatternConfig/Values']
        if value(ctx, resource, base + '/Field') == 'path-pattern':
            keys.append('/Values')
        for key in keys:
            values = value(ctx, resource, base + key)
            for j in range(len(values) if isinstance(values, list) else 0):
                local = _Context(design, resource)
                text = value(local, resource, f'{base}{key}/{j}')
                if not isinstance(text, str) or '{{' in text or '${' in text:
                    continue
                verdict = 'PASS' if len(text) <= 128 else 'FAIL'
                results.append(local.finding('ELBV2_RULE_PATH_PATTERN_LENGTH', f'{base}{key}/{j}', verdict,
                                             f'a path-pattern value has at most 128 characters ({len(text)} given)'))
    return results
