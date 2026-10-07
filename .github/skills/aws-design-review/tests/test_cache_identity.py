from pathlib import Path
import pytest
from aws_design_sheet.checks.elasticache.identities import evaluate_elasticache_identities
from aws_design_sheet.checks.cognito.stream_link_scope import evaluate_cognito_stream_link_scope
from aws_design_sheet.checks.registry import combine
cache_identity_checks = combine(evaluate_elasticache_identities, evaluate_cognito_stream_link_scope)
from aws_design_sheet.checker import Checker
from aws_design_sheet.models import TemplateContext
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('kind',['CacheCluster','ReplicationGroup'])
@pytest.mark.parametrize('mode',['same','different','other_region','fifo','wrong_service','invalid','unknown','dynamic','unknown_account'])
def test_notification(kind,mode):
    account='222222222222' if mode=='different' else '111111111111'
    region='us-east-1' if mode=='other_region' else 'ap-northeast-1'
    service='sqs' if mode=='wrong_service' else 'sns'
    raw=UNKNOWN if mode=='unknown' else {'Ref':'Topic'} if mode=='dynamic' else 'name' if mode=='invalid' else f'arn:aws:{service}:{region}:{account}:topic'+('.fifo' if mode=='fifo' else '')
    r=target('main','AWS::ElastiCache::'+kind,NotificationTopicArn=raw)
    if mode=='unknown_account':r.scope.account='unknown'
    expected='PASS' if mode in ('same','other_region','fifo') else 'FAIL' if mode=='different' else 'NEEDS_REVIEW'
    assert cache_identity_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('engine,expected',[('redis','PASS'),('valkey','PASS'),('Redis','NEEDS_REVIEW'),('VALKEY','NEEDS_REVIEW'),('memcached','FAIL'),('unknown','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('', 'NEEDS_REVIEW')])
def test_replication_engine(engine,expected):
    r=target('main','AWS::ElastiCache::ReplicationGroup',Engine=engine)
    assert cache_identity_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('engine',['redis','valkey',UNKNOWN])
@pytest.mark.parametrize('mode',['default','other','literal','conditional','scope','unknown','empty','id_default'])
def test_user_group(engine,mode):
    r=target('main','AWS::ElastiCache::UserGroup',Engine=engine,UserIds=[] if mode=='empty' else ['default' if mode=='id_default' else 'user-id'])
    user=target('user','AWS::ElastiCache::User',UserName='default' if mode=='default' else UNKNOWN if mode=='unknown' else 'other')
    d=linked_design(r,[user],[] if mode=='literal' else [('UserIds/0','user')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':user.scope.account='222222222222'
    expected='NEEDS_REVIEW' if engine!='redis' or mode in ('literal','conditional','scope','unknown') else 'PASS' if mode=='default' else 'FAIL'
    assert cache_identity_checks(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['same','account','region','environment','literal','conditional','duplicate','unknown','ancestor','name_mismatch','arn_name','template','wrong_type'])
def test_cognito_stream(mode):
    stream_name='arn:aws:kinesis:ap-northeast-1:111111111111:stream/name' if mode=='arn_name' else 'stream'
    r=target('main','AWS::Cognito::IdentityPool',CognitoStreams=UNKNOWN if mode=='ancestor' else {'StreamName':UNKNOWN if mode=='unknown' else stream_name})
    stream=target('stream','AWS::S3::Bucket' if mode=='wrong_type' else 'AWS::Kinesis::Stream',Name='different' if mode=='name_mismatch' else stream_name)
    links=[] if mode=='literal' else [('CognitoStreams/StreamName','stream')]
    if mode=='duplicate':links=links*2
    d=linked_design(r,[stream],links)
    if mode=='account':stream.scope.account='222222222222'
    if mode=='region':stream.scope.region='us-east-1'
    if mode=='environment':stream.scope.environment='other'
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='template':stream.template=TemplateContext(state='UNRESOLVED')
    expected='PASS' if mode=='same' else 'FAIL' if mode in ('account','region') else 'NEEDS_REVIEW'
    assert cache_identity_checks(d,r)[0]['verdict']==expected


def test_checker_notification():
    r=target('main','AWS::ElastiCache::CacheCluster',NotificationTopicArn='arn:aws:sns:ap-northeast-1:222222222222:topic')
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='CACHECLUSTER_NOTIFICATION_ACCOUNT' and f['verdict']=='FAIL' for f in results)
