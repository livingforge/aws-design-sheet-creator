"""ListenerRule conditions grounded in literal ARNs or same-scope links."""
import re
import ipaddress
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT

URL = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancingv2-listenerrule.html'
SOURCES = {'ELBV2_RULE_PRIORITY_DUPLICATE': [URL], 'ELBV2_RULE_APPLICATION_LISTENER': [URL]}
SOURCES['ELBV2_NLB_FORWARD_PROTOCOL'] = ['https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html']
SOURCES['ELBV2_ALB_TARGET_LISTENER_PORT'] = ['https://docs.aws.amazon.com/elasticloadbalancing/latest/network/application-load-balancer-target.html']
SOURCES['ELBV2_QUIC_SERVER_ID_DUPLICATE'] = ['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-elasticloadbalancingv2-targetgroup-targetdescription.html']
LISTENER = 'AWS::ElasticLoadBalancingV2::Listener'
RULE = 'AWS::ElasticLoadBalancingV2::ListenerRule'


def alb_target_listener_port(design, resource):
    ctx = _Context(design, resource)
    if value(ctx, resource, '/properties/TargetType') != 'alb':
        return []
    targets = value(ctx, resource, '/properties/Targets')
    if targets is ABSENT or targets == []:
        return []  # Targets may be registered later.
    port = value(ctx, resource, '/properties/Port')
    results = []
    for i in range(len(targets) if isinstance(targets, list) else 1):
        path = '/properties/Targets/' + str(i)
        lb = linked(ctx, resource, path + '/Id', 'AWS::ElasticLoadBalancingV2::LoadBalancer')
        matched = False
        if lb and type(port) is int:
            override = value(ctx, resource, path + '/Port')
            kind = value(ctx, lb, '/properties/Type')
            if override in (ABSENT, port) and kind in (ABSENT, 'application'):
                for listener in design.resources:
                    if listener.type != LISTENER:
                        continue
                    other_ctx = _Context(design, listener)
                    other_lb = linked(other_ctx, listener, '/properties/LoadBalancerArn', lb.type)
                    listener_port = value(other_ctx, listener, '/properties/Port')
                    if other_lb and other_lb.id == lb.id and type(listener_port) is int and listener_port == port:
                        ctx.evidence.extend(other_ctx.evidence)
                        matched = True
                        break
        results.append(ctx.finding('ELBV2_ALB_TARGET_LISTENER_PORT', path,
            'PASS' if matched else 'NEEDS_REVIEW',
            'a linked application load balancer has a listener on the target-group port' if matched else
            'no matching listener is proven; undeclared listeners, unresolved links and target port overrides require review'))
    return results


@resource_check('AWS::ElasticLoadBalancingV2::Listener')
def listener_forward_protocol(design, resource):
    ctx = _Context(design, resource)
    protocol = value(ctx, resource, '/properties/Protocol')
    allowed = {'TCP': ('TCP','TCP_UDP','TCP_QUIC'), 'TLS': ('TCP','TLS'),
               'UDP': ('UDP','TCP_UDP'), 'TCP_UDP': ('TCP_UDP',),
               'QUIC': ('QUIC','TCP_QUIC'), 'TCP_QUIC': ('TCP_QUIC',)}
    if not isinstance(protocol, str) or protocol not in allowed:
        return []
    path = '/properties/DefaultActions'
    actions = value(ctx, resource, path)
    verdicts = []
    linked_groups = {}
    if not isinstance(actions, list):
        verdicts.append('NEEDS_REVIEW')
    else:
        for i in range(len(actions)):
            base = path + '/' + str(i)
            kind = value(ctx, resource, base + '/Type')
            if kind != 'forward':
                if kind not in ('redirect','fixed-response','authenticate-cognito','authenticate-oidc','jwt-validation'):
                    verdicts.append('NEEDS_REVIEW')
                continue
            paths = []
            direct = base + '/TargetGroupArn'
            if value(ctx, resource, direct) is not ABSENT:
                paths.append(direct)
            groups_base = base + '/ForwardConfig/TargetGroups'
            groups = value(ctx, resource, groups_base)
            if isinstance(groups, list):
                paths.extend(groups_base + '/' + str(j) + '/TargetGroupArn' for j in range(len(groups)))
            elif groups is not ABSENT:
                verdicts.append('NEEDS_REVIEW')
            if not paths:
                verdicts.append('NEEDS_REVIEW')
            for target_path in paths:
                group = linked(ctx, resource, target_path, 'AWS::ElasticLoadBalancingV2::TargetGroup')
                if group:
                    linked_groups[group.id] = group
                target_protocol = value(ctx, group, '/properties/Protocol') if group else None
                verdicts.append('PASS' if target_protocol in allowed[protocol] else 'FAIL' if target_protocol in ('HTTP','HTTPS','TCP','TLS','UDP','TCP_UDP','QUIC','TCP_QUIC','GENEVE') else 'NEEDS_REVIEW')
    if not verdicts:
        return []
    verdict = 'FAIL' if 'FAIL' in verdicts else 'NEEDS_REVIEW' if 'NEEDS_REVIEW' in verdicts else 'PASS'
    results = [ctx.finding('ELBV2_NLB_FORWARD_PROTOCOL', path, verdict,
        'each proven target group must support the network listener protocol; unresolved, conditional and external references require review')]
    if protocol in ('QUIC', 'TCP_QUIC'):
        results.extend(quic_server_ids(ctx, linked_groups.values()))
    return results


def quic_server_ids(ctx, groups):
    seen = {}
    collision = False
    for group in groups:
        if value(ctx, group, '/properties/Protocol') not in ('QUIC','TCP_QUIC'):
            continue
        kind = value(ctx, group, '/properties/TargetType')
        kind = 'instance' if kind is ABSENT else kind
        targets = value(ctx, group, '/properties/Targets')
        for i in range(len(targets) if isinstance(targets, list) else 0):
            base = '/properties/Targets/' + str(i)
            server = value(ctx, group, base + '/QuicServerId')
            target_id = value(ctx, group, base + '/Id')
            identity = None
            if isinstance(target_id, str):
                if kind == 'instance' and re.fullmatch(r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})', target_id):
                    identity = ('instance', target_id)
                elif kind == 'ip':
                    try:
                        address = ipaddress.ip_address(target_id)
                        if '%' not in target_id:
                            identity = ('ip' + str(address.version), str(address))
                    except ValueError:
                        pass
            if identity and isinstance(server, str) and re.fullmatch(r'0x[0-9a-f]{16}', server):
                peers = seen.setdefault(server, set())
                collision |= any(peer[0] == identity[0] and peer != identity for peer in peers)
                peers.add(identity)
    return [ctx.finding('ELBV2_QUIC_SERVER_ID_DUPLICATE', '/properties/DefaultActions',
        'FAIL' if collision else 'NEEDS_REVIEW',
        'distinct declared targets share a QUIC server ID on this listener' if collision else
        'no proven collision among declared targets; external registrations, unresolved identities and aliases remain unverified')]


def listener_identity(ctx, resource):
    path = '/properties/ListenerArn'
    listener = linked(ctx, resource, path, LISTENER)
    if listener:
        return ('resource', listener.id), listener
    raw = value(ctx, resource, path)
    if isinstance(raw, str) and re.fullmatch(
            r'arn:[a-z0-9-]+:elasticloadbalancing:[a-z0-9-]+:[0-9]{12}:listener/(app|net|gwy)/[^{}\s]+', raw):
        return ('arn', raw), None
    return None, None


def evaluate_listener_links(design, resource):
    if resource.type != RULE:
        return []
    ctx = _Context(design, resource)
    identity, listener = listener_identity(ctx, resource)
    priority = value(ctx, resource, '/properties/Priority')
    collisions = []
    if identity and type(priority) is int:
        for other in design.resources:
            if other.id == resource.id or other.type != RULE:
                continue
            other_ctx = _Context(design, other)
            other_identity, _ = listener_identity(other_ctx, other)
            other_priority = value(other_ctx, other, '/properties/Priority')
            if other_identity == identity and type(other_priority) is int and other_priority == priority:
                collisions.append(other.id)
                ctx.evidence.extend(other_ctx.evidence)
    results = [ctx.finding('ELBV2_RULE_PRIORITY_DUPLICATE', '/properties/Priority',
        'FAIL' if collisions else 'NEEDS_REVIEW',
        'priority collides with design rules: ' + ', '.join(collisions) if collisions else
        'no proven duplicate in the design; unresolved references and existing AWS rules remain unverified')]
    kind = None
    if listener:
        lb = linked(ctx, listener, '/properties/LoadBalancerArn', 'AWS::ElasticLoadBalancingV2::LoadBalancer')
        if lb:
            raw_type = value(ctx, lb, '/properties/Type')
            kind = 'application' if raw_type is ABSENT else raw_type
    elif identity and identity[0] == 'arn':
        kind = {'app': 'application', 'net': 'network', 'gwy': 'gateway'}[
            identity[1].split(':listener/', 1)[1].split('/', 1)[0]]
    verdict = 'PASS' if kind == 'application' else 'FAIL' if kind in ('network', 'gateway') else 'NEEDS_REVIEW'
    results.append(ctx.finding('ELBV2_RULE_APPLICATION_LISTENER', '/properties/ListenerArn', verdict,
        'listener rules require an Application Load Balancer; unresolved links require review'))
    return results
