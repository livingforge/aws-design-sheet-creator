"""Explicit App Mesh property-map prerequisites and local identity checks."""
import re
from ..common.context_values import value
from ..common.field_reads import ABSENT, UNKNOWN

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-proxyconfiguration.html'
API='https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ProxyConfiguration.html'
GUIDE='https://docs.aws.amazon.com/app-mesh/latest/userguide/getting-started-ecs.html'
SOURCES={
    'ECS_PROXY_REQUIRED_PROPERTIES':[CF,API,GUIDE],
    'ECS_PROXY_IGNORED_UID':[CF,GUIDE],
    'ECS_PROXY_EGRESS_PORT_COUNT':[GUIDE],
    'ECS_PROXY_ESSENTIAL_CONTAINER':[GUIDE, 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-containerdefinition.html'],
}


def proxy_properties(ctx,resource):
    base='/properties/ProxyConfiguration'
    if value(ctx,resource,base) is ABSENT:
        return []
    path=base+'/ProxyConfigurationProperties'
    items=value(ctx,resource,path)
    kind=value(ctx,resource,base+'/Type')
    entries={}
    pending=not isinstance(items,list)
    for i in range(len(items) if isinstance(items,list) else 0):
        name=value(ctx,resource,path+f'/{i}/Name')
        if not isinstance(name,str) or '{{' in name or '${' in name:
            pending=True
        else:
            entries.setdefault(name,[]).append(value(ctx,resource,path+f'/{i}/Value'))
    def get(name):
        values=entries.get(name,[])
        return UNKNOWN if pending or len(values)>1 else values[0] if values else ABSENT
    required=[get(k) for k in ('AppPorts','ProxyIngressPort','ProxyEgressPort','EgressIgnoredPorts','EgressIgnoredIPs')]
    uid,gid=get('IgnoredUID'),get('IgnoredGID')
    known=lambda v:isinstance(v,str) and '{{' not in v and '${' not in v
    verdict='NEEDS_REVIEW'
    if kind=='APPMESH' and isinstance(items,list):
        missing=any(v is ABSENT for v in required) or all(v is ABSENT or v=='' for v in (uid,gid))
        if missing:
            verdict='FAIL'
        elif all(known(v) for v in required) and any(known(v) and v for v in (uid,gid)):
            verdict='PASS'
    results=[ctx.finding('ECS_PROXY_REQUIRED_PROPERTIES',path,verdict,
        'APPMESH requires the documented property keys and a nonempty IgnoredUID or IgnoredGID; empty egress exclusion strings are allowed; values and runtime support remain separate')]
    if kind!='APPMESH':
        return results
    name=value(ctx,resource,base+'/ContainerName')
    containers=value(ctx,resource,'/properties/ContainerDefinitions')
    matches=[]
    unknown_names=not isinstance(containers,list)
    for i in range(len(containers) if isinstance(containers,list) else 0):
        container=value(ctx,resource,f'/properties/ContainerDefinitions/{i}/Name')
        unknown_names |= not known(container)
        if known(name) and container==name:matches.append(i)
    essential=value(ctx,resource,f'/properties/ContainerDefinitions/{matches[0]}/Essential') if len(matches)==1 and not unknown_names else UNKNOWN
    results.append(ctx.finding('ECS_PROXY_ESSENTIAL_CONTAINER',base+'/ContainerName',
        'PASS' if essential is True or essential is ABSENT else 'FAIL' if essential is False else 'NEEDS_REVIEW',
        'the named App Mesh proxy container must be essential; TaskDefinition defaults omitted Essential to true'))
    if uid is not ABSENT and uid!='':
        user=value(ctx,resource,f'/properties/ContainerDefinitions/{matches[0]}/User') if len(matches)==1 and not unknown_names else UNKNOWN
        literal_uid=lambda v:known(v) and re.fullmatch(r'[0-9]{1,20}',v) is not None
        verdict=('PASS' if int(uid)==int(user) else 'FAIL') if literal_uid(uid) and literal_uid(user) else 'NEEDS_REVIEW'
        results.append(ctx.finding('ECS_PROXY_IGNORED_UID',path,verdict,
            'numeric IgnoredUID must match the named proxy container User; user/group names, compound User forms and runtime identity resolution need review'))
    ports=get('EgressIgnoredPorts')
    if ports is not ABSENT:
        verdict='NEEDS_REVIEW'
        if known(ports):
            parts=ports.split(',') if ports else []
            if all(re.fullmatch(r'[0-9]{1,5}',p) and 1<=int(p)<=65535 for p in parts):
                ports_set={int(p) for p in parts}
                verdict='FAIL' if len(ports_set)>15 else 'NEEDS_REVIEW' if len(ports_set)==15 and 22 not in ports_set else 'PASS'
        results.append(ctx.finding('ECS_PROXY_EGRESS_PORT_COUNT',path,verdict,
            'at most 15 distinct outbound ports may be ignored; the boundary without implicit port 22 and unsupported spellings need review'))
    return results
