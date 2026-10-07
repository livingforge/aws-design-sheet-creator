from pathlib import Path
import pytest
from aws_design_sheet.checks.bedrockagentcore.authorizer_maps import evaluate_bedrockagentcore_authorizer_maps
from aws_design_sheet.checks.certificatemanager.certificate import evaluate_certificatemanager_certificate
from aws_design_sheet.checks.cleanrooms.output_columns import evaluate_cleanrooms_output_columns, CLEAN
from aws_design_sheet.checks.registry import combine
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
policy_maps_checks=combine(evaluate_bedrockagentcore_authorizer_maps,evaluate_certificatemanager_certificate,evaluate_cleanrooms_output_columns)


def check(kind,rule=None,**props):
    r=target('subject',kind,**props)
    rows=policy_maps_checks(linked_design(r),r)
    return [x for x in rows if rule is None or x['rule_id']==rule]


@pytest.mark.parametrize('allowed,mapping,expected',[
    (['read'],{'read':'public'},'PASS'),(['read'],{'write':'public'},'FAIL'),
    (['read',UNKNOWN],{'write':'public'},'NEEDS_REVIEW'),
    (['read',UNKNOWN],{'read':UNKNOWN},'PASS'),
    (['read/a~b'],{'read/a~b':'public'},'PASS'),
    (UNKNOWN,{'read':'public'},'NEEDS_REVIEW'),(['read'],UNKNOWN,'NEEDS_REVIEW')])
def test_scope_keys(allowed,mapping,expected):
    assert check('AWS::BedrockAgentCore::Gateway',AuthorizerConfiguration={'CustomJWTAuthorizer':{
        'AllowedScopes':allowed,'AdvertisedScopeMapping':mapping}})[0]['verdict']==expected


@pytest.mark.parametrize('keys,dimensions,expected',[
    (['targetName','toolName'],{'targetName':'target','toolName':'*'},'PASS'),
    (['targetName','toolName'],{'toolName':'tool','targetName':'*'},'FAIL'),
    (['toolName','targetName'],{'toolName':'tool','targetName':'*'},'PASS'),
    (['targetName','toolName'],{'targetName':'*','toolName':'*'},'PASS'),
    (['targetName','toolName'],{'targetName':'target'},'FAIL'),
    (['targetName'],{'targetName':'target','extra':'*'},'FAIL'),
    (['targetName'],{'targetName':'prefix*'},'NEEDS_REVIEW'),
    (['targetName','toolName'],{'targetName':UNKNOWN,'toolName':'tool'},'NEEDS_REVIEW'),
    (['targetName',UNKNOWN],{'targetName':'target'},'NEEDS_REVIEW'),
    (['targetName','targetName'],{'targetName':'target'},'NEEDS_REVIEW'),
    (UNKNOWN,{'targetName':'target'},'NEEDS_REVIEW'),
    (['targetName'],UNKNOWN,'NEEDS_REVIEW')])
def test_dimension_order(keys,dimensions,expected):
    assert check('AWS::BedrockAgentCore::GatewayRateLimit',DimensionKeys=keys,Entries=[{'Dimensions':dimensions}])[0]['verdict']==expected


@pytest.mark.parametrize('key',['alg','typ','iss','sub','jti','exp'])
def test_reserved_claims(key):
    suffix='AdditionalHeaderClaims' if key in ('alg','typ') else 'AdditionalPayloadClaims'
    assert check('AWS::BedrockAgentCore::OAuth2CredentialProvider',Oauth2ProviderConfigInput={
        'CustomOauth2ProviderConfig':{'PrivateKeyJwtConfig':{suffix:{key:UNKNOWN}}}})[0]['verdict']=='FAIL'


@pytest.mark.parametrize('claims,expected',[({'custom':'x'},'PASS'),(UNKNOWN,'NEEDS_REVIEW'),({'${claim}':'x'},'NEEDS_REVIEW')])
def test_other_claims(claims,expected):
    assert check('AWS::BedrockAgentCore::OAuth2CredentialProvider',Oauth2ProviderConfigInput={
        'CustomOauth2ProviderConfig':{'PrivateKeyJwtConfig':{'AdditionalHeaderClaims':claims}}})[0]['verdict']==expected


@pytest.mark.parametrize('domain,validation,expected',[
    ('a.example.com','example.com','PASS'),('example.com','example.com','PASS'),
    ('badexample.com','example.com','FAIL'),('example.com','a.example.com','FAIL'),
    ('*.example.com','example.com','NEEDS_REVIEW'),('A.example.com','example.com','NEEDS_REVIEW'),
    ('xn--test.example.com','example.com','NEEDS_REVIEW'),(UNKNOWN,'example.com','NEEDS_REVIEW')])
def test_superdomain(domain,validation,expected):
    assert check('AWS::CertificateManager::Certificate','ACM_VALIDATION_SUPERDOMAIN',DomainValidationOptions=[
        {'DomainName':domain,'ValidationDomain':validation}])[0]['verdict']==expected


@pytest.mark.parametrize('domain,names,zone,expected',[
    ('example.com',['example.com'],'Z1','PASS'),('example.com',['other.com'],'Z1','FAIL'),
    ('example.com',['other.com'],None,'NEEDS_REVIEW'),('example.com',[UNKNOWN],'Z1','NEEDS_REVIEW'),
    ('*.example.com',['*.example.com'],'Z1','PASS'),('*.example.com',['example.com'],'Z1','FAIL'),
    ('example.com',['EXAMPLE.COM'],'Z1','NEEDS_REVIEW'),('example.com',['example.com',UNKNOWN],'Z1','PASS')])
def test_dns_membership(domain,names,zone,expected):
    options=[{'DomainName':n,**({'HostedZoneId':zone} if zone else {})} for n in names]
    assert check('AWS::CertificateManager::Certificate','ACM_DNS_DOMAIN_MEMBERSHIP',DomainName=domain,
        ValidationMethod='DNS',DomainValidationOptions=options)[0]['verdict']==expected


def test_private_and_email_skip_dns_membership():
    props={'DomainName':'example.com','DomainValidationOptions':[{'DomainName':'other.com','HostedZoneId':'Z1'}]}
    assert not check('AWS::CertificateManager::Certificate','ACM_DNS_DOMAIN_MEMBERSHIP',ValidationMethod='EMAIL',**props)
    assert not check('AWS::CertificateManager::Certificate','ACM_DNS_DOMAIN_MEMBERSHIP',ValidationMethod='DNS',CertificateAuthorityArn=UNKNOWN,**props)


@pytest.mark.parametrize('kind',list(CLEAN))
@pytest.mark.parametrize('names,expected',[(['a','b'],'PASS'),(['a','a'],'FAIL'),(['a',UNKNOWN],'NEEDS_REVIEW'),(['a','a',UNKNOWN],'FAIL')])
def test_output_columns(kind,names,expected):
    assert check('AWS::CleanRooms::'+kind,AnalysisRules=[{'Policy':{'V1':{'Custom':{'AggregationThresholds':[
        {'OutputColumnThresholds':[{'OutputColumnName':n} for n in names]}]}}}}])[0]['verdict']==expected


def test_checker_sources_and_evidence():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::CleanRooms::ConfiguredTable',AnalysisRules=[{'Policy':{'V1':{'Custom':{'AggregationThresholds':[
        {'OutputColumnThresholds':[{'OutputColumnName':'a'},{'OutputColumnName':'a'}]}]}}}}])
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    row=next(r for r in result['results'] if r['rule_id']=='CLEANROOMS_CONFIGURED_OUTPUT_COLUMNS')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
