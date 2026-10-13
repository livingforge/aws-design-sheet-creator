"""Checks for AWS::Lightsail::Instance."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'LIGHTSAIL_TCP_UDP_PORTS': [CF+'aws-properties-lightsail-instance-port.html'],
}


def port_bounds(ctx,resource,path):
    if value(ctx,resource,path+'/Protocol') not in ('tcp','udp'):return 'NEEDS_REVIEW'
    ports=[value(ctx,resource,path+'/'+key) for key in ('FromPort','ToPort')]
    if any(type(p) is int and not 0<=p<=65535 for p in ports):return 'FAIL'
    return 'PASS' if all(type(p) is int for p in ports) else 'NEEDS_REVIEW'


@resource_check('AWS::Lightsail::Instance')
def evaluate_lightsail_tcp_udp_ports(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::Lightsail::Instance':
        for path in expand(ctx,resource,'/properties/Networking/Ports/*'):
            emit('LIGHTSAIL_TCP_UDP_PORTS',path,port_bounds(ctx,resource,path),'explicit TCP/UDP endpoints must be integers within 0..65535; omitted endpoints, unknown/non-TCP/UDP protocols, ICMP/v6 semantics and protocol enumeration remain held')
    return results
