from pathlib import Path
import pytest
from aws_design_sheet.checks.dms.subnet_group_zones import evaluate_dms_subnet_group_zones
from aws_design_sheet.checks.dsql.witness_region import evaluate_dsql_witness_region
from aws_design_sheet.checks.databrew.metadata_service import evaluate_databrew_metadata_service
from aws_design_sheet.checks.cognito.log_group_account_encryption import evaluate_cognito_log_group_account_encryption
from aws_design_sheet.checks.registry import combine
data_regions_checks = combine(evaluate_dms_subnet_group_zones, evaluate_dsql_witness_region, evaluate_databrew_metadata_service, evaluate_cognito_log_group_account_encryption)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('zones,expected',[(['ap-northeast-1a','ap-northeast-1c'],'PASS'),(['ap-northeast-1a']*2,'FAIL'),(['ap-northeast-1a'],'FAIL'),([],'FAIL'),(['ap-northeast-1a',UNKNOWN],'NEEDS_REVIEW'),(['ap-northeast-1a','us-east-1a'],'NEEDS_REVIEW')])
@pytest.mark.parametrize('mode',['linked','literal','conditional','scope'])
def test_subnet_zones(zones,expected,mode):
    r=target('main','AWS::DMS::ReplicationSubnetGroup',SubnetIds=[f's{i}' for i in range(len(zones))])
    subnets=[target(f's{i}','AWS::EC2::Subnet',AvailabilityZone=z) for i,z in enumerate(zones)]
    d=linked_design(r,subnets,[] if mode=='literal' else [(f'SubnetIds/{i}',s.id) for i,s in enumerate(subnets)])
    if mode=='conditional':
        for relation in d.relations:relation.condition='Maybe'
    if mode=='scope':
        for subnet in subnets:subnet.scope.account='222222222222'
    assert data_regions_checks(d,r)[0]['verdict']==(expected if mode=='linked' or not zones else 'NEEDS_REVIEW')


@pytest.mark.parametrize('region,expected',[('ap-northeast-1','FAIL'),('us-east-1','PASS'),(UNKNOWN,'NEEDS_REVIEW'),('${Region}','NEEDS_REVIEW'),('invalid','NEEDS_REVIEW')])
def test_witness(region,expected):
    r=target('main','AWS::DSQL::Cluster',MultiRegionProperties={'WitnessRegion':region})
    assert data_regions_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('arn,expected',[('arn:aws:appflow:us-east-1:111111111111:flow/a','PASS'),('arn:aws:lambda:us-east-1:111111111111:function:f','FAIL'),('not-an-arn','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_metadata(arn,expected):
    r=target('main','AWS::DataBrew::Dataset',Input={'Metadata':{'SourceArn':arn}})
    assert data_regions_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('kms,expected',[(None,'PASS'),('arn:aws:kms:ap-northeast-1:111111111111:key/abc','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
@pytest.mark.parametrize('mode',['linked','conditional_group','conditional_pool','scope_group','scope_pool'])
def test_cognito_encryption(kms,expected,mode):
    r=target('main','AWS::Cognito::LogDeliveryConfiguration',LogConfigurations=[{'CloudWatchLogsConfiguration':{}}])
    pool=target('pool','AWS::Cognito::UserPool')
    group=target('group','AWS::Logs::LogGroup',**({} if kms is None else {'KmsKeyId':kms}))
    d=linked_design(r,[pool,group],[('UserPoolId','pool'),('LogConfigurations/0/CloudWatchLogsConfiguration/LogGroupArn','group')])
    if mode=='conditional_group':d.relations[1].condition='Maybe'
    if mode=='conditional_pool':d.relations[0].condition='Maybe'
    if mode=='scope_group':group.scope.account='222222222222'
    if mode=='scope_pool':pool.scope.account='222222222222'
    wanted='FAIL' if mode=='scope_group' else expected if mode=='linked' or expected=='FAIL' and mode in ('conditional_pool','scope_pool') else 'NEEDS_REVIEW'
    assert data_regions_checks(d,r)[0]['verdict']==wanted


@pytest.mark.parametrize('account,expected',[('111111111111','NEEDS_REVIEW'),('222222222222','FAIL')])
@pytest.mark.parametrize('pool_linked',[True,False])
def test_cognito_literal_owner(account,expected,pool_linked):
    r=target('main','AWS::Cognito::LogDeliveryConfiguration',LogConfigurations=[{'CloudWatchLogsConfiguration':{'LogGroupArn':f'arn:aws:logs:us-east-1:{account}:log-group:group'}}])
    pool=target('pool','AWS::Cognito::UserPool')
    d=linked_design(r,[pool],[('UserPoolId','pool')] if pool_linked else [])
    assert data_regions_checks(d,r)[0]['verdict']==(expected if pool_linked else 'NEEDS_REVIEW')


def test_checker_witness():
    r=target('main','AWS::DSQL::Cluster',MultiRegionProperties={'WitnessRegion':'ap-northeast-1'})
    root=Path(__file__).resolve().parents[1]
    findings=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='DSQL_WITNESS_REGION' and f['verdict']=='FAIL' for f in findings)
