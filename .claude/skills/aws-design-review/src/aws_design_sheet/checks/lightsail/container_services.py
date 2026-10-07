"""Checks for AWS::Lightsail::Container, AWS::Lightsail::LoadBalancerTlsCertificate."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'LIGHTSAIL_CONTAINER_VALUES': [CF+'aws-resource-lightsail-container.html',CF+'aws-properties-lightsail-container-portinfo.html'],
    'LIGHTSAIL_CONTAINER_HEALTH': [CF+'aws-properties-lightsail-container-healthcheckconfig.html'],
    'LIGHTSAIL_CONTAINER_DOMAINS': [CF+'aws-resource-lightsail-container.html'],
    'LIGHTSAIL_CERTIFICATE_WILDCARDS': [CF+'aws-resource-lightsail-loadbalancertlscertificate.html'],
}


@resource_check('AWS::Lightsail::Container', 'AWS::Lightsail::LoadBalancerTlsCertificate')
def evaluate_lightsail_container_services(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Lightsail::Container':
        checks=[('/properties/Power',('nano','micro','small','medium','large','xlarge'))]
        pattern='/properties/ContainerServiceDeployment/Containers/*/Ports/*/Protocol'
        checks.extend((p,('HTTP','HTTPS','TCP','UDP')) for p in expand(ctx,resource,pattern))
        for path,allowed in checks:
            raw=get(path)
            if raw is ABSENT:continue
            emit('LIGHTSAIL_CONTAINER_VALUES',path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','checks documented literal container power/protocol values; omitted optional members and unresolved values remain separate')
        root='/properties/ContainerServiceDeployment/PublicEndpoint/HealthCheckConfig'
        for key,low,high in (('IntervalSeconds',5,300),('TimeoutSeconds',2,60)):
            path=root+'/'+key;raw=get(path)
            if raw is not ABSENT:
                emit('LIGHTSAIL_CONTAINER_HEALTH',path,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if low<=raw<=high else 'FAIL','checks explicit integer health-check interval/timeout bounds; unknown values remain under review')
        path=root+'/SuccessCodes';raw=get(path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW';numbers=None
            if isinstance(raw,str):
                if re.fullmatch(r'[0-9]{3}(?:,[0-9]{3})*',raw):numbers=[int(x) for x in raw.split(',')]
                elif re.fullmatch(r'[0-9]{3}-[0-9]{3}',raw):
                    a,b=map(int,raw.split('-'))
                    if a<=b:numbers=[a,b]
                if numbers is not None:verdict='PASS' if all(200<=x<=499 for x in numbers) else 'FAIL'
            emit('LIGHTSAIL_CONTAINER_HEALTH',path,verdict,'checks HTTP success codes 200..499 for explicit single/comma-separated codes or one ascending range; other grammar and unknown values remain under review')
        path='/properties/PublicDomainNames';raw=get(path)
        if raw is not ABSENT:
            names=[];pending=not isinstance(raw,list)
            for i in range(len(raw)) if isinstance(raw,list) else ():
                p=path+'/'+str(i)+'/DomainNames';domains=get(p)
                if not isinstance(domains,list):pending=True;continue
                for j in range(len(domains)):
                    name=get(p+'/'+str(j))
                    if literal(name) and name.isascii() and re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+',name):names.append(name.lower())
                    else:pending=True
            distinct=set(names);pending|=len(distinct)!=len(names)
            emit('LIGHTSAIL_CONTAINER_DOMAINS',path,'FAIL' if len(distinct)>4 else 'NEEDS_REVIEW' if pending else 'PASS','at most four distinct literal public domains across all DomainNames arrays; duplicates, nonstandard/unknown names and certificate existence/validation remain under review')
    if resource.type=='AWS::Lightsail::LoadBalancerTlsCertificate':
        for path in expand(ctx,resource,'/properties/CertificateAlternativeNames/*'):
            raw=get(path)
            emit('LIGHTSAIL_CERTIFICATE_WILDCARDS',path,'NEEDS_REVIEW' if not literal(raw) else 'FAIL' if '*' in raw else 'PASS','wildcard alternative certificate names are unsupported; unknown values and actual certificate validity remain under review')
    return results
