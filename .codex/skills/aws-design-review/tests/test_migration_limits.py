from pathlib import Path
import pytest
from aws_design_sheet.checks.dms.migration_limits import DCUS, evaluate_dms_migration_limits
from aws_design_sheet.checks.dax.notification_owner import evaluate_dax_notification_owner
from aws_design_sheet.checks.dlm.default_public_values import evaluate_dlm_default_public_values
from aws_design_sheet.checks.codepipeline.custom_public_values import evaluate_codepipeline_custom_public_values
from aws_design_sheet.checks.arczonalshift.autoshift_resource_type import evaluate_arczonalshift_autoshift_resource_type
from aws_design_sheet.checks.registry import combine
migration_limits_checks = combine(evaluate_dax_notification_owner, evaluate_dlm_default_public_values, evaluate_dms_migration_limits, evaluate_codepipeline_custom_public_values, evaluate_arczonalshift_autoshift_resource_type)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(kind,props,rule=None):
    r=target('main',kind,**props)
    return [f for f in migration_limits_checks(linked_design(r),r) if rule is None or f['rule_id']==rule]


@pytest.mark.parametrize('owner,expected',[('111111111111','PASS'),('222222222222','FAIL')])
@pytest.mark.parametrize('region',['ap-northeast-1','us-east-1'])
def test_dax_owner(owner,expected,region):
    assert check('AWS::DAX::Cluster',{'NotificationTopicARN':f'arn:aws:sns:{region}:{owner}:topic'})[0]['verdict']==expected


@pytest.mark.parametrize('raw',[UNKNOWN,'${Topic}','topic','arn:aws:sns:us-east-1:*:topic'])
def test_dax_unknown(raw):
    assert check('AWS::DAX::Cluster',{'NotificationTopicARN':raw})[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('field,lo,hi',[('CreateInterval',1,7),('RetainInterval',2,14)])
@pytest.mark.parametrize('mode',['low','high','below','above','unknown','boolean'])
def test_dlm_range(field,lo,hi,mode):
    raw={'low':lo,'high':hi,'below':lo-1,'above':hi+1,'unknown':UNKNOWN,'boolean':True}[mode]
    f=check('AWS::DLM::LifecyclePolicy',{'DefaultPolicy':'VOLUME',field:raw})
    assert f[0]['verdict']==('PASS' if mode in ('low','high') else 'FAIL' if mode in ('below','above') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('extra',[{}, {'DefaultPolicy':UNKNOWN}, {'DefaultPolicy':'VOLUME','PolicyDetails':{}}, {'DefaultPolicy':'CUSTOM'}])
def test_dlm_applicability(extra):
    assert check('AWS::DLM::LifecyclePolicy',{'CreateInterval':99,**extra})[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('units',list(DCUS)+[0,3,385,True,UNKNOWN])
@pytest.mark.parametrize('field',['MinCapacityUnits','MaxCapacityUnits'])
def test_dcu(field,units):
    expected='NEEDS_REVIEW' if type(units) is not int else 'PASS' if units in DCUS else 'FAIL'
    assert check('AWS::DMS::ReplicationConfig',{'ComputeConfig':{field:units}})[0]['verdict']==expected


@pytest.mark.parametrize('source,expected',[('replication-instance','PASS'),('replication-task','PASS'),('database','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_source(source,expected):
    assert check('AWS::DMS::EventSubscription',{'SourceType':source})[0]['verdict']==expected


@pytest.mark.parametrize('field,raw,expected',[('Category','Build','PASS'),('Category','Other','FAIL'),('Provider','a'*35,'PASS'),('Provider','a'*36,'FAIL'),('Provider','bad.name','FAIL'),('Version','v1-a','PASS'),('Version','a'*10,'FAIL'),('Version',UNKNOWN,'NEEDS_REVIEW'),('ConfigurationProperties',[{}]*10,'PASS'),('ConfigurationProperties',[{}]*11,'FAIL')],ids=['category','bad_category','provider_max','provider_long','provider_syntax','version','version_long','unknown','props_max','props_over'])
def test_custom_values(field,raw,expected):
    assert check('AWS::CodePipeline::CustomActionType',{field:raw})[0]['verdict']==expected


@pytest.mark.parametrize('side',['InputArtifactDetails','OutputArtifactDetails'])
@pytest.mark.parametrize('bound',['MinimumCount','MaximumCount'])
@pytest.mark.parametrize('raw,expected',[(0,'PASS'),(5,'PASS'),(-1,'FAIL'),(6,'FAIL'),(True,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_artifact_counts(side,bound,raw,expected):
    assert check('AWS::CodePipeline::CustomActionType',{side:{bound:raw}})[0]['verdict']==expected


@pytest.mark.parametrize('kind,expected',[('app','PASS'),('net','PASS'),('gwy','FAIL')])
def test_arc_arn(kind,expected):
    arn=f'arn:aws:elasticloadbalancing:ap-northeast-1:111111111111:loadbalancer/{kind}/lb/123abc'
    assert check('AWS::ARCZonalShift::ZonalAutoshiftConfiguration',{'ResourceIdentifier':arn})[0]['verdict']==expected


@pytest.mark.parametrize('kind',['application','network','gateway',None])
@pytest.mark.parametrize('mode',['linked','literal','conditional','scope'])
def test_arc_link(kind,mode):
    r=target('main','AWS::ARCZonalShift::ZonalAutoshiftConfiguration',ResourceIdentifier='lb')
    lb=target('lb','AWS::ElasticLoadBalancingV2::LoadBalancer',**({} if kind is None else {'Type':kind}))
    d=linked_design(r,[lb],[] if mode=='literal' else [('ResourceIdentifier','lb')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':lb.scope.account='222222222222'
    expected='NEEDS_REVIEW' if mode!='linked' or kind is None else 'FAIL' if kind=='gateway' else 'PASS'
    assert migration_limits_checks(d,r)[0]['verdict']==expected


def test_checker_dcu():
    r=target('main','AWS::DMS::ReplicationConfig',ComputeConfig={'MaxCapacityUnits':3})
    root=Path(__file__).resolve().parents[1]
    findings=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='DMS_CAPACITY_UNIT_VALUES' and f['verdict']=='FAIL' for f in findings)
