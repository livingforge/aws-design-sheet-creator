"""Checks for AWS::ElasticLoadBalancing::LoadBalancer."""
from __future__ import annotations

from ..registry import resource_check
from ..common.design_uniqueness import _Context
from ..common.field_reads import ABSENT, read


SOURCES = {
    "ELB_LISTENER_INSTANCE_PORT_PROTOCOL": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-elasticloadbalancing-loadbalancer-listeners.html"],
}


@resource_check('AWS::ElasticLoadBalancing::LoadBalancer')
def classic_listener_protocols(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/Listeners'
    listeners = read(ctx, resource, path)
    if listeners is ABSENT:
        return []
    pending = not isinstance(listeners, list)
    ports = {}
    for i in range(len(listeners) if isinstance(listeners, list) else 0):
        port = read(ctx, resource, path + f'/{i}/InstancePort')
        protocol = read(ctx, resource, path + f'/{i}/InstanceProtocol')
        if isinstance(port, str) and port.isdigit():
            port = int(port)
        if type(port) is not int or protocol not in ('HTTP', 'HTTPS', 'TCP', 'SSL'):
            pending = True
            continue
        secure = protocol in ('HTTPS', 'SSL')
        if port in ports and ports[port] != secure:
            return [ctx.finding('ELB_LISTENER_INSTANCE_PORT_PROTOCOL', path, 'FAIL',
                                'listeners on one instance port must all be secure or all insecure')]
        ports[port] = secure
    return [ctx.finding('ELB_LISTENER_INSTANCE_PORT_PROTOCOL', path,
                        'NEEDS_REVIEW' if pending else 'PASS',
                        'listeners on one instance port must all be secure or all insecure')]
