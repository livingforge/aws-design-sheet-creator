"""mTLS ownership evidence derivable from explicit ACM declarations."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'APIGATEWAY_MTLS_PRIVATE_CA_OWNERSHIP':[
    CF+'aws-resource-apigateway-domainname.html',
    CF+'aws-properties-apigatewayv2-domainname-domainnameconfiguration.html',
    CF+'aws-resource-certificatemanager-certificate.html',
    'https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html']}


@resource_check('AWS::ApiGateway::DomainName', 'AWS::ApiGatewayV2::DomainName')
def domain_certificates(design,resource):
    ctx=_Context(design,resource)
    root='/properties'
    mtls=value(ctx,resource,root+'/MutualTlsAuthentication')
    if mtls is ABSENT:return []
    uri=value(ctx,resource,root+'/MutualTlsAuthentication/TruststoreUri')
    configured=isinstance(uri,str) and re.fullmatch(r's3://[a-z0-9.-]+/[^{}]+',uri) is not None
    if resource.type=='AWS::ApiGateway::DomainName':
        configs=[(root,root+'/RegionalCertificateArn')]
    else:
        items=value(ctx,resource,root+'/DomainNameConfigurations')
        if not isinstance(items,list):
            return [ctx.finding('APIGATEWAY_MTLS_PRIVATE_CA_OWNERSHIP',root+'/DomainNameConfigurations','NEEDS_REVIEW','domain certificate configurations are unresolved')]
        configs=[(root+f'/DomainNameConfigurations/{i}',root+f'/DomainNameConfigurations/{i}/CertificateArn') for i in range(len(items))]
    rows=[]
    for base,cert_path in configs:
        certificate=linked(ctx,resource,cert_path,'AWS::CertificateManager::Certificate')
        ca=value(ctx,certificate,'/properties/CertificateAuthorityArn') if certificate else UNKNOWN
        authority=linked(ctx,certificate,'/properties/CertificateAuthorityArn','AWS::ACMPCA::CertificateAuthority') if certificate else None
        private=authority is not None or isinstance(ca,str) and re.fullmatch(r'arn:[a-z0-9-]+:acm-pca:[a-z0-9-]+:\d{12}:certificate-authority/[a-zA-Z0-9-]+',ca) is not None
        path=base+'/OwnershipVerificationCertificateArn'
        owner=value(ctx,resource,path)
        declared_owner=linked(ctx,resource,path,'AWS::CertificateManager::Certificate')
        verdict='NEEDS_REVIEW'
        if configured and private:
            if owner is ABSENT or owner=='':verdict='FAIL'
            elif declared_owner or isinstance(owner,str) and re.fullmatch(r'arn:[a-z0-9-]+:acm:[a-z0-9-]+:\d{12}:certificate/[a-zA-Z0-9-]+',owner):verdict='PASS'
        elif configured and certificate and ca is ABSENT:
            verdict='NOT_APPLICABLE'
        rows.append(ctx.finding('APIGATEWAY_MTLS_PRIVATE_CA_OWNERSHIP',path,verdict,
            'a linked private-CA server certificate with configured mTLS requires ownership certificate declaration; ownership certificate issuer, domain coverage, validity and imported/external server certificates remain separate'))
    return rows
