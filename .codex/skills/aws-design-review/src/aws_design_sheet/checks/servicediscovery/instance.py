"""Checks for AWS::ServiceDiscovery::Instance."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SERVICEDISCOVERY_ALIAS_SERVICE': [CF+'aws-resource-servicediscovery-instance.html',CF+'aws-properties-servicediscovery-service-dnsconfig.html',CF+'aws-properties-servicediscovery-service-dnsrecord.html'],
    'SERVICEDISCOVERY_ALIAS_ATTRIBUTES': [CF+'aws-resource-servicediscovery-instance.html'],
}


@resource_check('AWS::ServiceDiscovery::Instance')
def evaluate_servicediscovery_instance(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::ServiceDiscovery::Instance':
        path='/properties/InstanceAttributes';alias=get(path+'/AWS_ALIAS_DNS_NAME')
        if alias is not ABSENT:
            raw=get(path);pending=not literal(alias) or not isinstance(raw,dict);invalid=False
            known={'AWS_INSTANCE_CNAME','AWS_INSTANCE_IPV4','AWS_INSTANCE_IPV6','AWS_INSTANCE_PORT'}
            if isinstance(raw,dict):
                for key in raw:
                    if key in known:
                        item=get(path+'/'+key)
                        if literal(alias) and literal(item):invalid=True
                        elif item is not ABSENT:pending=True
                    elif key.startswith('AWS_INSTANCE'):pending=True
            emit('SERVICEDISCOVERY_ALIAS_ATTRIBUTES',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','alias cannot coexist with documented AWS_INSTANCE_CNAME/IPV4/IPV6/PORT values; unknown values and other AWS_INSTANCE-prefixed keys remain under review')
            service=linked(ctx,resource,'/properties/ServiceId','AWS::ServiceDiscovery::Service') if known_scope(resource) else None
            verdict='NEEDS_REVIEW'
            if service and literal(alias):
                records=value(ctx,service,'/properties/DnsConfig/DnsRecords');policy=value(ctx,service,'/properties/DnsConfig/RoutingPolicy')
                types=[value(ctx,service,'/properties/DnsConfig/DnsRecords/'+str(i)+'/Type') for i in range(len(records))] if isinstance(records,list) else []
                has_address=any(t in ('A','AAAA') for t in types)
                complete=isinstance(records,list) and all(literal(t) for t in types)
                invalid=literal(policy) and policy!='WEIGHTED' or complete and not has_address
                verdict='FAIL' if invalid else 'PASS' if policy=='WEIGHTED' and has_address else 'NEEDS_REVIEW'
            emit('SERVICEDISCOVERY_ALIAS_SERVICE','/properties/ServiceId',verdict,'explicit linked service for alias needs an A/AAAA record and WEIGHTED routing; absent policy is not defaulted; external/conditional/cross-scope service links and actual ELB target remain under review')
    return results
