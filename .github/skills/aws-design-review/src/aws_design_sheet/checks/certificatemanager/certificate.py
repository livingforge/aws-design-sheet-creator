"""Checks for AWS::CertificateManager::Certificate."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from ..common.policy_maps import plain_domain

SOURCES = {
    'ACM_VALIDATION_SUPERDOMAIN': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-certificatemanager-certificate-domainvalidationoption.html',
    ],
    'ACM_DNS_DOMAIN_MEMBERSHIP': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-certificatemanager-certificate.html',
    ],
}


@resource_check('AWS::CertificateManager::Certificate')
def evaluate_certificatemanager_certificate(design,resource):
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::CertificateManager::Certificate':
        path='/properties/DomainValidationOptions'; raw=value(ctx,resource,path)
        for base in expand(ctx,resource,path+'/*/ValidationDomain'):
            validation=value(ctx,resource,base); domain=value(ctx,resource,base.rsplit('/',1)[0]+'/DomainName')
            verdict='NEEDS_REVIEW'
            if plain_domain(validation) and plain_domain(domain):verdict='PASS' if domain==validation or domain.endswith('.'+validation) else 'FAIL'
            emit('ACM_VALIDATION_SUPERDOMAIN',base,verdict,'compares literal lowercase ASCII label boundaries; wildcard, IDN, uppercase, trailing dot and unknown names remain under review')
        method=value(ctx,resource,'/properties/ValidationMethod'); ca=value(ctx,resource,'/properties/CertificateAuthorityArn')
        if raw is not ABSENT and method not in ('EMAIL','HTTP') and ca is ABSENT:
            domain=value(ctx,resource,'/properties/DomainName'); names=[]; automatic=False; pending=method!='DNS' or not isinstance(raw,list) or not plain_domain(domain,True)
            for i in range(len(raw)) if isinstance(raw,list) else ():
                base=path+'/'+str(i); name=value(ctx,resource,base+'/DomainName'); zone=value(ctx,resource,base+'/HostedZoneId')
                names.append(name)
                if not plain_domain(name,True):pending=True
                if literal(zone):automatic=True
            verdict='PASS' if method=='DNS' and plain_domain(domain,True) and domain in names else 'FAIL' if automatic and not pending else 'NEEDS_REVIEW'
            emit('ACM_DNS_DOMAIN_MEMBERSHIP',path,verdict,'checks exact domain membership for public automatic DNS validation; failure requires explicit HostedZoneId and complete names; manual validation, ownership and hosted-zone existence remain external')
    return results
