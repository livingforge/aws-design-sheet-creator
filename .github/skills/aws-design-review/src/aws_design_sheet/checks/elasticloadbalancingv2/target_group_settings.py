"""Target group settings that Elastic Load Balancing refuses although cfn-lint 1.57.2 accepts them.

Each was refused by AWS in aws-emulator-evaluation-suite:

- a health check timeout not below the interval ("Health check interval must be greater than the
  timeout.");
- ProtocolVersion on a target group whose protocol is not HTTP or HTTPS ("You cannot specify the
  protocol version for a target group with the 'TCP' protocol");
- slow start together with least_outstanding_requests ("You cannot enable both slow start and
  least outstanding requests algorithm on a target group");
- a target ID of the wrong kind for the target type ("The IP address 'i-...' is not a valid IPv4
  address");
- an IPv4 target outside the VPC, RFC1918 and RFC6598 ("must be an address from a VPC subnet,
  RFC1918, or RFC6598");
- a health check path not starting with '/' ("Health check path ... must begin with a '/'
  character");
- an attribute of the other load balancer family ("A target group with TCP protocol does not
  support the attribute slow_start.duration_seconds", "Stickiness type 'lb_cookie' is not
  supported for target groups with the TCP protocol");
- weighted_random with stickiness ("You cannot have both stickiness and weighted random
  algorithm enabled on the same target group.").

Timeout and interval are compared only when both are given, since their defaults depend on the
protocol and target type.
"""
import ipaddress
import re

from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.index import relations_from

TYPE = 'AWS::ElasticLoadBalancingV2::TargetGroup'
CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
TG = CF + 'aws-resource-elasticloadbalancingv2-targetgroup.html'
ALB = 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/'
SOURCES = {
    'ELBV2_HEALTH_CHECK_TIMEOUT_BELOW_INTERVAL': [TG, 'https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html'],
    'ELBV2_PROTOCOL_VERSION_HTTP_ONLY': [TG, ALB + 'load-balancer-target-groups.html'],
    'ELBV2_SLOW_START_LEAST_OUTSTANDING': [CF + 'aws-properties-elasticloadbalancingv2-targetgroup-targetgroupattribute.html',
                                           ALB + 'edit-target-group-attributes.html'],
    'ELBV2_TARGET_ID_MATCHES_TYPE': [CF + 'aws-properties-elasticloadbalancingv2-targetgroup-targetdescription.html'],
    'ELBV2_IP_TARGET_ALLOWED_RANGE': [CF + 'aws-properties-elasticloadbalancingv2-targetgroup-targetdescription.html',
                                      ALB + 'load-balancer-target-groups.html'],
    'ELBV2_HEALTH_CHECK_PATH_SLASH': [TG],
    'ELBV2_TARGET_GROUP_ATTRIBUTE_PROTOCOL': [
        ALB + 'edit-target-group-attributes.html',
        'https://docs.aws.amazon.com/elasticloadbalancing/latest/network/edit-target-group-attributes.html'],
    'ELBV2_WEIGHTED_RANDOM_STICKINESS': [ALB + 'edit-target-group-attributes.html'],
}
HTTP_FAMILY = ('HTTP', 'HTTPS')
NETWORK_FAMILY = ('TCP', 'TLS', 'UDP', 'TCP_UDP')
# (attribute, refused value or None for any value) for each protocol family
REFUSED = {
    HTTP_FAMILY: [('stickiness.type', 'source_ip'), ('preserve_client_ip.enabled', None),
                  ('proxy_protocol_v2.enabled', None), ('lambda.multi_value_headers.enabled', None)],
    NETWORK_FAMILY: [('stickiness.type', 'lb_cookie'), ('stickiness.type', 'app_cookie'),
                     ('load_balancing.algorithm.type', 'least_outstanding_requests'),
                     ('slow_start.duration_seconds', None)],
}
PRIVATE = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10')]


def _int(raw):
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    return int(raw) if isinstance(raw, str) and raw.isdigit() else None


def _attributes(ctx, resource):
    """Literal TargetGroupAttributes by key; None when a key or the list is unresolved."""
    items = value(ctx, resource, '/properties/TargetGroupAttributes')
    if items is ABSENT:
        return {}
    if not isinstance(items, list):
        return None
    found = {}
    for i in range(len(items)):
        key = value(ctx, resource, f'/properties/TargetGroupAttributes/{i}/Key')
        if not isinstance(key, str) or '{{' in key:
            return None
        found.setdefault(key, []).append(value(ctx, resource, f'/properties/TargetGroupAttributes/{i}/Value'))
    return {key: values[0] if len(values) == 1 else UNKNOWN for key, values in found.items()}


def _health_check(ctx, resource):
    timeout = value(ctx, resource, '/properties/HealthCheckTimeoutSeconds')
    interval = value(ctx, resource, '/properties/HealthCheckIntervalSeconds')
    if timeout is ABSENT or interval is ABSENT:
        return []
    low, high = _int(timeout), _int(interval)
    if low is None or high is None:
        verdict, reason = 'NEEDS_REVIEW', 'health check timeout or interval is unresolved'
    elif low >= high:
        verdict, reason = 'FAIL', f'health check timeout {low} must be below the interval {high}'
    else:
        verdict, reason = 'PASS', 'health check timeout is below the interval'
    return [ctx.finding('ELBV2_HEALTH_CHECK_TIMEOUT_BELOW_INTERVAL', '/properties/HealthCheckTimeoutSeconds', verdict, reason)]


def _protocol_version(ctx, resource):
    if value(ctx, resource, '/properties/ProtocolVersion') is ABSENT:
        return []
    protocol = value(ctx, resource, '/properties/Protocol')
    if protocol in ('HTTP', 'HTTPS'):
        verdict, reason = 'PASS', 'ProtocolVersion is set on an HTTP or HTTPS target group'
    elif isinstance(protocol, str):
        verdict, reason = 'FAIL', f'ProtocolVersion applies only to HTTP and HTTPS target groups, not {protocol}'
    else:
        verdict, reason = 'NEEDS_REVIEW', 'target group protocol is unresolved or omitted'
    return [ctx.finding('ELBV2_PROTOCOL_VERSION_HTTP_ONLY', '/properties/ProtocolVersion', verdict, reason)]


def _slow_start(ctx, resource):
    attributes = _attributes(ctx, resource)
    if attributes is None:
        return []
    slow = attributes.get('slow_start.duration_seconds', ABSENT)
    algorithm = attributes.get('load_balancing.algorithm.type', ABSENT)
    if slow is ABSENT or algorithm is ABSENT:
        return []
    if not isinstance(slow, str) or not slow.isdigit() or not isinstance(algorithm, str) or '{{' in algorithm:
        verdict, reason = 'NEEDS_REVIEW', 'slow start or load balancing algorithm is unresolved'
    elif int(slow) > 0 and algorithm == 'least_outstanding_requests':
        verdict, reason = 'FAIL', 'slow start cannot be enabled with the least_outstanding_requests algorithm'
    else:
        verdict, reason = 'PASS', 'slow start and the load balancing algorithm are compatible'
    return [ctx.finding('ELBV2_SLOW_START_LEAST_OUTSTANDING', '/properties/TargetGroupAttributes', verdict, reason)]


def _id_kind(raw):
    if not isinstance(raw, str) or '{{' in raw or '${' in raw:
        return None
    if re.fullmatch(r'i-[0-9a-f]{8,17}', raw):
        return 'instance'
    try:
        ipaddress.ip_address(raw)
        return 'ip'
    except ValueError:
        pass
    if re.fullmatch(r'arn:[a-z0-9-]+:lambda:.+', raw):
        return 'lambda'
    if re.fullmatch(r'arn:[a-z0-9-]+:elasticloadbalancing:.+:loadbalancer/app/.+', raw):
        return 'alb'
    return 'other'


# (expression, target type, attribute) -> the kind of ID the reference returns.
LINKED_KIND = {('Ref', 'AWS::EC2::Instance', None): 'instance',
               ('GetAtt', 'AWS::EC2::Instance', 'PrivateIp'): 'ip',
               ('GetAtt', 'AWS::EC2::Instance', 'PublicIp'): 'ip',
               ('GetAtt', 'AWS::Lambda::Function', 'Arn'): 'lambda',
               ('Ref', 'AWS::ElasticLoadBalancingV2::LoadBalancer', None): 'alb',
               ('GetAtt', 'AWS::ElasticLoadBalancingV2::LoadBalancer', 'LoadBalancerArn'): 'alb'}


def _linked_kind(resource, path):
    """Kind of ID a Ref/GetAtt target returns; None when the expression is not recorded."""
    hint = resource.template.reference_hints.get(path) if resource.template else None
    return LINKED_KIND.get((hint.kind, hint.target_type, hint.attribute)) if hint else None


def _vpc_networks(ctx, resource):
    """Literal IPv4 CIDRs of the target group's linked VPC, or None when they are not all known."""
    vpc = linked(ctx, resource, '/properties/VpcId', 'AWS::EC2::VPC')
    if vpc is None:
        return None
    blocks = [value(ctx, vpc, '/properties/CidrBlock')]
    for other in ctx.design.resources:
        if other.type == 'AWS::EC2::VPCCidrBlock' and any(
                r.source_path == '/properties/VpcId' and r.target_resource_id == vpc.id
                for r in relations_from(ctx.design, other.id)):
            block = value(ctx, other, '/properties/CidrBlock')
            if block is not ABSENT or value(ctx, other, '/properties/Ipv4IpamPoolId') is not ABSENT:
                blocks.append(block)
    try:
        return [ipaddress.ip_network(b) for b in blocks]
    except (TypeError, ValueError):
        return None


def _targets(design, resource):
    ctx = _Context(design, resource)
    targets = value(ctx, resource, '/properties/Targets')
    if not isinstance(targets, list):
        return []
    target_type = value(ctx, resource, '/properties/TargetType')
    expected = 'instance' if target_type is ABSENT else target_type
    results = []
    for i in range(len(targets)):
        path = f'/properties/Targets/{i}/Id'
        local = _Context(design, resource)
        member = next((r for r in relations_from(design, resource.id) if r.source_path == path), None)
        if member is not None:
            kind = _linked_kind(resource, path)
        else:
            kind = _id_kind(value(local, resource, path))
        if expected not in ('instance', 'ip', 'lambda', 'alb'):
            verdict, reason = 'NEEDS_REVIEW', 'target type is unresolved'
        elif kind is None or kind == 'other':
            verdict, reason = 'NEEDS_REVIEW', 'target ID is unresolved or of an unrecognised form'
        else:
            verdict = 'PASS' if kind == expected else 'FAIL'
            reason = f'a target of an {expected} target group must be an {expected} target, not an {kind} target'
        results.append(local.finding('ELBV2_TARGET_ID_MATCHES_TYPE', path, verdict, reason))
        if expected == 'ip' and kind == 'ip' and member is None:
            address = ipaddress.ip_address(value(local, resource, path))
            if address.version != 4:
                continue
            if any(address in net for net in PRIVATE):
                verdict, reason = 'PASS', 'the target address is in RFC1918 or RFC6598'
            else:
                networks = _vpc_networks(local, resource)
                if networks is None:
                    verdict, reason = 'NEEDS_REVIEW', "the target group's VPC or its CIDR blocks are unresolved"
                elif any(address in net for net in networks):
                    verdict, reason = 'PASS', "the target address is in the target group's VPC"
                else:
                    verdict, reason = 'FAIL', "an IPv4 target must be in the target group's VPC, RFC1918 or RFC6598"
            results.append(local.finding('ELBV2_IP_TARGET_ALLOWED_RANGE', path, verdict, reason))
    return results


@resource_check(TYPE)
def evaluate_target_group_settings(design, resource):
    ctx = lambda: _Context(design, resource)  # noqa: E731 - one evidence trail per finding
    return (_health_check(ctx(), resource) + _protocol_version(ctx(), resource)
            + _slow_start(ctx(), resource) + _targets(design, resource)
            + _health_check_path(ctx(), resource) + _attribute_protocol(ctx(), resource)
            + _weighted_random(ctx(), resource))


def _health_check_path(ctx, resource):
    path = value(ctx, resource, '/properties/HealthCheckPath')
    if not isinstance(path, str) or '{{' in path or '${' in path:
        return []
    verdict = 'PASS' if path.startswith('/') else 'FAIL'
    return [ctx.finding('ELBV2_HEALTH_CHECK_PATH_SLASH', '/properties/HealthCheckPath', verdict,
                        "the health check path begins with '/'")]


def _attribute_protocol(ctx, resource):
    attributes = _attributes(ctx, resource)
    protocol = value(ctx, resource, '/properties/Protocol')
    family = next((f for f in REFUSED if protocol in f), None)
    if not attributes or family is None:
        return []
    refused = sorted({key for key, banned in REFUSED[family]
                      if key in attributes and (banned is None or attributes[key] == banned)})
    verdict = 'FAIL' if refused else 'PASS'
    reason = (f'a {protocol} target group does not support ' + ', '.join(refused) if refused
              else f'the attributes suit a {protocol} target group')
    return [ctx.finding('ELBV2_TARGET_GROUP_ATTRIBUTE_PROTOCOL', '/properties/TargetGroupAttributes', verdict, reason)]


def _weighted_random(ctx, resource):
    attributes = _attributes(ctx, resource)
    if not attributes or attributes.get('load_balancing.algorithm.type') != 'weighted_random':
        return []
    sticky = attributes.get('stickiness.enabled', ABSENT)
    if sticky is ABSENT:
        return []
    if sticky not in ('true', 'false'):
        verdict, reason = 'NEEDS_REVIEW', 'stickiness.enabled is unresolved'
    else:
        verdict = 'FAIL' if sticky == 'true' else 'PASS'
        reason = 'weighted_random cannot be used with stickiness enabled'
    return [ctx.finding('ELBV2_WEIGHTED_RANDOM_STICKINESS', '/properties/TargetGroupAttributes', verdict, reason)]
