"""Checks for these resource types:

- AWS::CertificateManager::AcmeDomainValidation
- AWS::CertificateManager::AcmeExternalAccountBinding
- AWS::CertificateManager::Certificate
"""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'ACME_DOMAIN_SCOPE_VALUES': [CF+'aws-properties-certificatemanager-acmedomainvalidation-domainscope.html'],
    'ACME_EXPIRATION_UNIT': [CF+'aws-properties-certificatemanager-acmeexternalaccountbinding-expiration.html'],
    'ACM_HOSTED_ZONE_DNS': [CF+'aws-properties-certificatemanager-certificate-domainvalidationoption.html',CF+'aws-resource-certificatemanager-certificate.html'],
    'ACM_PRIVATE_KEY_FAMILY': [CF+'aws-resource-certificatemanager-certificate.html'],
}


@resource_check(
    'AWS::CertificateManager::AcmeDomainValidation',
    'AWS::CertificateManager::AcmeExternalAccountBinding',
    'AWS::CertificateManager::Certificate',
)
def evaluate_certificatemanager_certificates(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):
        result=ctx.finding(rule,p,v,reason);result['source_checked_at']='2026-10-04';results.append(result)
    def enum(rule,p,allowed):
        raw=get(p)
        if raw is not ABSENT:emit(rule,p,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','literal value checked against current explicit CF allowed values; no omitted values inferred')
    if resource.type=='AWS::CertificateManager::AcmeDomainValidation':
        for key in ('ExactDomain','Subdomains','Wildcards'):
            enum('ACME_DOMAIN_SCOPE_VALUES','/properties/PrevalidationOptions/DnsPrevalidation/DomainScope/'+key,('ENABLED','DISABLED'))
    if resource.type=='AWS::CertificateManager::AcmeExternalAccountBinding':
        enum('ACME_EXPIRATION_UNIT','/properties/Expiration/Type',('MINUTES','HOURS','DAYS'))
    if resource.type=='AWS::CertificateManager::Certificate':
        ca_path='/properties/CertificateAuthorityArn';private=get(ca_path) is not ABSENT
        for p in expand(ctx,resource,'/properties/DomainValidationOptions/*/HostedZoneId'):
            method=get('/properties/ValidationMethod');zone=get(p);v='NEEDS_REVIEW'
            if not private and literal(zone):
                if method is ABSENT or method in ('EMAIL','HTTP'):v='FAIL'
                elif method=='DNS':v='PASS'
            emit('ACM_HOSTED_ZONE_DNS',p,v,'explicit HostedZoneId on a public certificate requires DNS; absent ValidationMethod uses documented EMAIL default; private/unknown inputs held')
        if private:
            ca=linked(ctx,resource,ca_path,'AWS::ACMPCA::CertificateAuthority');own=get('/properties/KeyAlgorithm');other=value(ctx,ca,'/properties/KeyAlgorithm') if ca else None
            def family(raw):
                return 'RSA' if raw in ('RSA_1024','RSA_2048','RSA_3072','RSA_4096') else 'EC' if raw in ('EC_prime256v1','EC_secp384r1','EC_secp521r1') else None
            a,b=family(own),family(other)
            emit('ACM_PRIVATE_KEY_FAMILY','/properties/KeyAlgorithm','NEEDS_REVIEW' if a is None or b is None else 'PASS' if a==b else 'FAIL','explicit certificate and linked CA key families agree; omitted defaults, external/conditional CA, unknown algorithms and service-specific certificate support held')
    return results
