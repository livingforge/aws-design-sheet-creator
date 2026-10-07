import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN

CA='arn:aws:acm-pca:ap-northeast-1:111111111111:certificate-authority/ca-id'
OWNER='arn:aws:acm:ap-northeast-1:111111111111:certificate/owner-id'


@pytest.mark.parametrize('v2',[False,True])
@pytest.mark.parametrize('ca,owner,change,expected',[
    (CA,None,'none','FAIL'),(CA,'','none','FAIL'),(CA,OWNER,'none','PASS'),
    (CA,UNKNOWN,'none','NEEDS_REVIEW'),(UNKNOWN,None,'none','NEEDS_REVIEW'),
    (None,None,'none','NOT_APPLICABLE'),
    (CA,None,'conditional','NEEDS_REVIEW'),(CA,None,'region','NEEDS_REVIEW'),
    (CA,None,'unknown-uri','NEEDS_REVIEW'),(CA,None,'empty-uri','NEEDS_REVIEW'),
])
def test_mtls_private_certificate_requirement(v2,ca,owner,change,expected):
    path='DomainNameConfigurations/0/CertificateArn' if v2 else 'RegionalCertificateArn'
    config={'CertificateArn' if v2 else 'RegionalCertificateArn':{'Ref':'cert'}}
    if owner is not None:config['OwnershipVerificationCertificateArn']=owner
    props={'DomainNameConfigurations':[config]} if v2 else config
    props['MutualTlsAuthentication']={'TruststoreUri':UNKNOWN if change=='unknown-uri' else '' if change=='empty-uri' else 's3://trust-bucket/trust.pem'}
    main=target('domain','AWS::ApiGatewayV2::DomainName' if v2 else 'AWS::ApiGateway::DomainName',**props)
    cert=target('cert','AWS::CertificateManager::Certificate',**({'CertificateAuthorityArn':ca} if ca is not None else {}))
    if change=='region':cert.scope.region='us-west-2'
    data=linked_design(main,[cert],[(path,'cert')])
    if change=='conditional':data.relations[0].condition='optional'
    assert next(r['verdict'] for r in run_resource_checks(data,main) if r['rule_id']=='APIGATEWAY_MTLS_PRIVATE_CA_OWNERSHIP')==expected


def test_absent_mtls_is_not_subject_to_rule():
    main=target('domain','AWS::ApiGateway::DomainName')
    assert not any(r['rule_id']=='APIGATEWAY_MTLS_PRIVATE_CA_OWNERSHIP' for r in run_resource_checks(linked_design(main),main))
