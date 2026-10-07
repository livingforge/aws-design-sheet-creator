from pathlib import Path
import pytest
from aws_design_sheet.checks.cassandra.certificates import evaluate_cassandra_certificates
from aws_design_sheet.checks.certificatemanager.certificates import evaluate_certificatemanager_certificates
from aws_design_sheet.checks.cleanrooms.collaborations import evaluate_cleanrooms_collaborations
from aws_design_sheet.checks.cleanroomsml.training_role_account import evaluate_cleanroomsml_training_role_account
from aws_design_sheet.checks.cloudformation.custom_resource_token_region import evaluate_cloudformation_custom_resource_token_region
from aws_design_sheet.checks.registry import combine
cassandra_certificates_checks = combine(evaluate_cassandra_certificates, evaluate_certificatemanager_certificates, evaluate_cleanrooms_collaborations, evaluate_cleanroomsml_training_role_account, evaluate_cloudformation_custom_resource_token_region)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,props,rule,targets=(),links=(),mutate=None):
    resource=target('main','AWS::'+kind,**props)
    design=linked_design(resource,targets,links)
    if mutate:mutate(design)
    return [r for r in cassandra_certificates_checks(design,resource) if r['rule_id']==rule]


@pytest.mark.parametrize('regions,expected',[(['ap-northeast-1','us-east-1'],'PASS'),(['us-east-1','us-west-2'],'FAIL'),(['ap-northeast-1',UNKNOWN],'PASS'),(['us-east-1',UNKNOWN],'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),([],'FAIL')])
def test_keyspace_region(regions,expected):
    assert check('Cassandra::Keyspace',{'ReplicationSpecification':{'RegionList':regions}},'KEYSPACE_DEPLOYMENT_REGION')[0]['verdict']==expected


@pytest.mark.parametrize('strategy,expected',[('MULTI_REGION','PASS'),('SINGLE_REGION','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_replica_applicability(strategy,expected):
    parent=target('keyspace','AWS::Cassandra::Keyspace',ReplicationSpecification={'ReplicationStrategy':strategy})
    assert check('Cassandra::Table',{'ReplicaSpecifications':[]},'CASSANDRA_REPLICA_APPLICABILITY',[parent],[('KeyspaceName','keyspace')])[0]['verdict']==expected


@pytest.mark.parametrize('type_name',['TEXT STATIC','text static','INT\tSTATIC'])
@pytest.mark.parametrize('cluster,expected',[(None,'FAIL'),([],'FAIL'),([{'Column':{'ColumnName':'sort','ColumnType':'TEXT'}}],'PASS'),(UNKNOWN,'NEEDS_REVIEW')])
def test_static_column(type_name,cluster,expected):
    props={'RegularColumns':[{'ColumnName':'x','ColumnType':type_name}]}
    if cluster is not None:props['ClusteringKeyColumns']=cluster
    assert check('Cassandra::Table',props,'CASSANDRA_STATIC_CLUSTERING')[0]['verdict']==expected


@pytest.mark.parametrize('type_name',['"STATIC"','frozen<list<text>> STATIC','text /* STATIC */',UNKNOWN])
def test_complex_type_held(type_name):
    assert check('Cassandra::Table',{'RegularColumns':[{'ColumnType':type_name}]},'CASSANDRA_STATIC_CLUSTERING')[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('key',['ExactDomain','Subdomains','Wildcards'])
@pytest.mark.parametrize('raw,expected',[('ENABLED','PASS'),('DISABLED','PASS'),('enabled','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_acme_domain_scope(key,raw,expected):
    assert check('CertificateManager::AcmeDomainValidation',{'PrevalidationOptions':{'DnsPrevalidation':{'DomainScope':{key:raw}}}},'ACME_DOMAIN_SCOPE_VALUES')[0]['verdict']==expected


@pytest.mark.parametrize('raw,expected',[('MINUTES','PASS'),('HOURS','PASS'),('DAYS','PASS'),('SECONDS','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_expiration(raw,expected):
    assert check('CertificateManager::AcmeExternalAccountBinding',{'Expiration':{'Type':raw}},'ACME_EXPIRATION_UNIT')[0]['verdict']==expected


@pytest.mark.parametrize('method,expected',[('DNS','PASS'),('EMAIL','FAIL'),('HTTP','FAIL'),(None,'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
@pytest.mark.parametrize('private',[False,True])
def test_hosted_zone(method,expected,private):
    props={'DomainValidationOptions':[{'HostedZoneId':'Z123'}]}
    if method is not None:props['ValidationMethod']=method
    if private:props['CertificateAuthorityArn']='external'
    assert check('CertificateManager::Certificate',props,'ACM_HOSTED_ZONE_DNS')[0]['verdict']==('NEEDS_REVIEW' if private else expected)


@pytest.mark.parametrize('own,ca,expected',[('RSA_2048','RSA_4096','PASS'),('EC_prime256v1','EC_secp384r1','PASS'),('RSA_2048','EC_prime256v1','FAIL'),('EC_prime256v1','RSA_2048','FAIL'),(UNKNOWN,'RSA_2048','NEEDS_REVIEW'),('RSA_2048',UNKNOWN,'NEEDS_REVIEW'),('FUTURE','RSA_2048','NEEDS_REVIEW')])
def test_ca_family(own,ca,expected):
    parent=target('ca','AWS::ACMPCA::CertificateAuthority',KeyAlgorithm=ca)
    assert check('CertificateManager::Certificate',{'KeyAlgorithm':own},'ACM_PRIVATE_KEY_FAMILY',[parent],[('CertificateAuthorityArn','ca')])[0]['verdict']==expected


@pytest.mark.parametrize('creator',[False,True])
@pytest.mark.parametrize('abilities,flag,expected',[(['CAN_QUERY','CAN_RUN_JOB'],False,'FAIL'),(['CAN_QUERY','CAN_RUN_JOB'],True,'PASS'),(['CAN_QUERY'],False,'NEEDS_REVIEW'),(['CAN_RUN_JOB'],False,'NEEDS_REVIEW'),(UNKNOWN,False,'NEEDS_REVIEW'),(['CAN_QUERY','CAN_RUN_JOB'],UNKNOWN,'NEEDS_REVIEW')])
def test_job_payer(creator,abilities,flag,expected):
    payment={'JobCompute':{'IsResponsible':flag}}
    props={'CreatorMemberAbilities':abilities,'CreatorPaymentConfiguration':payment} if creator else {'Members':[{'MemberAbilities':abilities,'PaymentConfiguration':payment}]}
    assert check('CleanRooms::Collaboration',props,'CLEANROOMS_JOB_PAYER_ABILITIES')[0]['verdict']==expected


@pytest.mark.parametrize('key,value',[('AggregationThresholds',[{}]),('ComparisonControls',{})])
@pytest.mark.parametrize('analyses,expected',[(['ANY_JOB'],'FAIL'),(['ANY_JOB','ANY_JOB'],'FAIL'),(['ANY_QUERY','ANY_JOB'],'NEEDS_REVIEW'),(['ANY_JOB',UNKNOWN],'NEEDS_REVIEW'),([],'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_job_only(key,value,analyses,expected):
    props={'AnalysisRules':[{'Policy':{'V1':{'Custom':{'AllowedAnalyses':analyses,key:value}}}}]}
    assert check('CleanRooms::IntermediateTable',props,'CLEANROOMS_INTERMEDIATE_JOB_ONLY')[0]['verdict']==expected


@pytest.mark.parametrize('own,expected_flag,verdict',[(True,True,'PASS'),(False,False,'PASS'),(True,False,'FAIL'),(False,True,'FAIL'),(UNKNOWN,False,'NEEDS_REVIEW'),(False,UNKNOWN,'NEEDS_REVIEW')])
def test_creator_membership(own,expected_flag,verdict):
    collab=target('collab','AWS::CleanRooms::Collaboration',CreatorPaymentConfiguration={'JobCompute':{'IsResponsible':expected_flag}})
    assert check('CleanRooms::Membership',{'PaymentConfiguration':{'JobCompute':{'IsResponsible':own}}},'CLEANROOMS_CREATOR_JOB_PAYMENT',[collab],[('CollaborationIdentifier','collab')])[0]['verdict']==verdict


@pytest.mark.parametrize('engine,expected',[('SPARK','PASS'),('CLEAN_ROOMS_SQL','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('FUTURE','NEEDS_REVIEW')])
@pytest.mark.parametrize('flag',[True,False])
def test_output_engine(engine,expected,flag):
    collab=target('collab','AWS::CleanRooms::Collaboration',AnalyticsEngine=engine)
    props={'DefaultResultConfiguration':{'OutputConfiguration':{'S3':{'SingleFileOutput':flag}}}}
    assert check('CleanRooms::Membership',props,'CLEANROOMS_SINGLE_FILE_ENGINE',[collab],[('CollaborationIdentifier','collab')])[0]['verdict']==expected


@pytest.mark.parametrize('mode',['literal','conditional','scope'])
def test_membership_unproven(mode):
    collab=target('collab','AWS::CleanRooms::Collaboration',CreatorPaymentConfiguration={'JobCompute':{'IsResponsible':False}})
    def mutate(design):
        if mode=='conditional':design.relations[0].condition='Maybe'
        if mode=='scope':collab.scope.account='222222222222'
    props={'CollaborationIdentifier':'external','PaymentConfiguration':{'JobCompute':{'IsResponsible':True}}}
    result=check('CleanRooms::Membership',props,'CLEANROOMS_CREATOR_JOB_PAYMENT',[collab],[] if mode=='literal' else [('CollaborationIdentifier','collab')],mutate)
    assert result[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('account,expected',[('111111111111','PASS'),('222222222222','FAIL')])
def test_training_account(account,expected):
    assert check('CleanRoomsML::TrainingDataset',{'RoleArn':f'arn:aws:iam::{account}:role/path/training'},'CLEANROOMSML_TRAINING_ROLE_ACCOUNT')[0]['verdict']==expected


@pytest.mark.parametrize('service',['sns','lambda'])
@pytest.mark.parametrize('region,expected',[('ap-northeast-1','PASS'),('us-east-1','FAIL')])
def test_custom_region(service,region,expected):
    assert check('CloudFormation::CustomResource',{'ServiceToken':f'arn:aws:{service}:{region}:111111111111:function:handler'},'CUSTOM_RESOURCE_TOKEN_REGION')[0]['verdict']==expected


@pytest.mark.parametrize('kind,props,rule',[
    ('Cassandra::Keyspace',{'ReplicationSpecification':UNKNOWN},'KEYSPACE_DEPLOYMENT_REGION'),
    ('CleanRoomsML::TrainingDataset',{'RoleArn':UNKNOWN},'CLEANROOMSML_TRAINING_ROLE_ACCOUNT'),
    ('CloudFormation::CustomResource',{'ServiceToken':UNKNOWN},'CUSTOM_RESOURCE_TOKEN_REGION')])
def test_unknown_inputs(kind,props,rule):
    assert check(kind,props,rule)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_integration():
    resource=target('main','AWS::Cassandra::Keyspace',ReplicationSpecification={'RegionList':['us-east-1','us-west-2']})
    root=Path(__file__).resolve().parents[1]
    result=next(r for r in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(resource))['results'] if r['rule_id']=='KEYSPACE_DEPLOYMENT_REGION')
    assert result['verdict']=='FAIL' and result['source_urls']
