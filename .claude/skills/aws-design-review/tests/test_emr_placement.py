from pathlib import Path
import pytest
from aws_design_sheet.checks.emrcontainers.log_rotation_size import rotation_size, evaluate_emrcontainers_log_rotation_size
from aws_design_sheet.checks.emr.placement import evaluate_emr_placement
from aws_design_sheet.checks.config.distinct_channel_limit import evaluate_config_distinct_channel_limit
from aws_design_sheet.checks.registry import combine
emr_placement_checks = combine(evaluate_emr_placement, evaluate_emrcontainers_log_rotation_size, evaluate_config_distinct_channel_limit)
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('raw,expected',[
    ('2KB','PASS'),('2Kb','PASS'),('2K','PASS'),('1.999KB','FAIL'),('0K','FAIL'),
    ('1MB','PASS'),('2GB','PASS'),('2.001GB','FAIL'),('2000M','PASS'),('2001M','NEEDS_REVIEW'),
    ('2048MB','NEEDS_REVIEW'),('2049M','FAIL'),('0.002MB','PASS'),('0.00198MB','NEEDS_REVIEW'),
    ('0.001MB','FAIL'),('2kb','NEEDS_REVIEW'),('2e0K','NEEDS_REVIEW'),('NaNG','NEEDS_REVIEW'),
    (' 2KB','NEEDS_REVIEW'),('2K\n','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),(2000,'NEEDS_REVIEW'),
    ('9999999999999G','NEEDS_REVIEW'),('${Size}','NEEDS_REVIEW'),
])
def test_rotation(raw,expected):
    assert rotation_size(raw)==expected


@pytest.mark.parametrize('fleet',[True,False])
@pytest.mark.parametrize('role',['Master','Core','Task'])
@pytest.mark.parametrize('mode',['same','opposite','unknown','literal','conditional','scope','empty'])
def test_cluster_mode(fleet,role,mode):
    kind='Fleet' if fleet else 'Group'
    selected=('Group' if fleet else 'Fleet') if mode=='opposite' else kind
    field=role+'Instance'+selected+('s' if role=='Task' else '')
    config=UNKNOWN if mode=='unknown' else [] if role=='Task' and mode=='empty' else {} if mode=='empty' else [{'Name':'nodes'}] if role=='Task' else {'Name':'nodes'}
    r=target('main','AWS::EMR::Instance'+kind+'Config',**{('ClusterId' if fleet else 'JobFlowId'):'cluster'})
    cluster=target('cluster','AWS::EMR::Cluster',Instances={field:config})
    path='ClusterId' if fleet else 'JobFlowId'
    d=linked_design(r,[cluster],[] if mode=='literal' else [(path,'cluster')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':cluster.scope.region='us-east-1'
    assert emr_placement_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='opposite' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['distinct','same_name','unknown','absent','other_account','other_region','other_environment','template_unknown','single'])
def test_channel_count(mode):
    r=target('main','AWS::Config::DeliveryChannel',Name='first')
    other=target('second','AWS::Config::DeliveryChannel',**({} if mode=='absent' else {'Name':UNKNOWN if mode=='unknown' else 'first' if mode=='same_name' else 'second'}))
    if mode=='other_account':other.scope.account='222222222222'
    if mode=='other_region':other.scope.region='us-east-1'
    if mode=='other_environment':other.scope.environment='other'
    if mode=='template_unknown':other.template=TemplateContext(state='UNRESOLVED')
    d=linked_design(r,[] if mode=='single' else [other])
    assert emr_placement_checks(d,r)[0]['verdict']==('FAIL' if mode=='distinct' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('config',[UNKNOWN,{'MonitoringConfiguration':UNKNOWN},{'MonitoringConfiguration':{'ContainerLogRotationConfiguration':UNKNOWN}}])
def test_rotation_unknown_ancestors(config):
    r=target('main','AWS::EMRContainers::Endpoint',ConfigurationOverrides=config)
    assert emr_placement_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_rotation():
    r=target('main','AWS::EMRContainers::Endpoint',ConfigurationOverrides={'MonitoringConfiguration':{'ContainerLogRotationConfiguration':{'RotationSize':'1KB'}}})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='EMRCONTAINERS_LOG_ROTATION_SIZE' and f['verdict']=='FAIL' for f in results)
