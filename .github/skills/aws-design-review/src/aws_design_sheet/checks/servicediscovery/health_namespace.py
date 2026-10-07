"""Checks for AWS::ServiceDiscovery::Service."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SERVICEDISCOVERY_HEALTH_NAMESPACE': [CF+'aws-properties-servicediscovery-service-healthcheckconfig.html',CF+'aws-resource-servicediscovery-service.html',CF+'aws-properties-servicediscovery-service-dnsconfig.html'],
}


def namespace_target(ctx,resource,path):
    for name in ('PublicDnsNamespace','HttpNamespace','PrivateDnsNamespace'):
        target=linked(ctx,resource,path,'AWS::ServiceDiscovery::'+name)
        if target:return target
    return None


@resource_check('AWS::ServiceDiscovery::Service')
def evaluate_servicediscovery_health_namespace(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::ServiceDiscovery::Service':
        path='/properties/HealthCheckConfig';health=get(path)
        if health is not ABSENT:
            targets=[];pending=not isinstance(health,dict) or not known_scope(resource)
            for p in ('/properties/NamespaceId','/properties/DnsConfig/NamespaceId'):
                if get(p) is ABSENT:continue
                namespace=namespace_target(ctx,resource,p) if known_scope(resource) else None
                if namespace:targets.append(namespace)
                else:pending=True
            pending|=not targets or len({x.id for x in targets})>1
            verdict='NEEDS_REVIEW' if pending else 'FAIL' if targets[0].type=='AWS::ServiceDiscovery::PrivateDnsNamespace' else 'PASS'
            emit('SERVICEDISCOVERY_HEALTH_NAMESPACE',path,verdict,'HealthCheckConfig is for explicit public DNS or HTTP namespace targets; private DNS is invalid; conditional/external/cross-scope references, conflicting root/nested namespace selectors and unknown health settings remain under review')
    return results
