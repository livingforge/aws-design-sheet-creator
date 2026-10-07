from pathlib import Path
import pytest
from aws_design_sheet.checks.batch.platform_guard import evaluate_batch_platform_guard, GUARDED
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.fixture(scope='module')
def checker():
    root=Path(__file__).resolve().parents[1]
    return Checker(root/'schemas',root/'profiles/vpc-subnet.json')


@pytest.mark.parametrize('platform',[['EC2','FARGATE'],['FARGATE','EC2'],['FARGATE',UNKNOWN],[],UNKNOWN,['Future'],[UNKNOWN]])
def test_legacy_guard(checker,platform):
    r=target('job','AWS::Batch::JobDefinition',PlatformCapabilities=platform,Type='multinode',ContainerProperties={'Memory':1,'NetworkConfiguration':{},'LogConfiguration':{'LogDriver':'fluentd'}})
    rows=[f for f in checker.check(linked_design(r))['results'] if f['rule_id'] in GUARDED]
    assert len(rows)==5 and all(f['verdict']=='NEEDS_REVIEW' and f['dependencies'] for f in rows)


@pytest.mark.parametrize('platform,expected',[(['FARGATE'],'FAIL'),(['EC2'],'NOT_APPLICABLE'),(['MANAGED_INSTANCES'],'NOT_APPLICABLE')])
def test_known_mode(checker,platform,expected):
    r=target('job','AWS::Batch::JobDefinition',PlatformCapabilities=platform,Type='multinode')
    rows=checker.check(linked_design(r))['results']
    assert next(f for f in rows if f['rule_id']=='BATCH.JOBDEFINITION.FARGATE_NOT_MULTINODE')['verdict']==expected


def test_absent_default_preserved(checker):
    r=target('job','AWS::Batch::JobDefinition',ContainerProperties={'NetworkConfiguration':{}})
    rows=checker.check(linked_design(r))['results']
    assert next(f for f in rows if f['rule_id']=='BATCH.JOBDEFINITION.EC2_NO_FARGATE_CONTAINER_SETTINGS')['verdict']=='FAIL'


@pytest.mark.parametrize('case',['valid','missing_ecs','container','multinode','nodes','unknown'])
def test_managed(case):
    props={'EcsProperties':UNKNOWN if case=='unknown' else {},'Type':'multinode' if case=='multinode' else 'container'}
    if case=='missing_ecs':props.pop('EcsProperties')
    if case=='container':props['ContainerProperties']={}
    if case=='nodes':props['NodeProperties']={}
    r=target('job','AWS::Batch::JobDefinition',PlatformCapabilities=['MANAGED_INSTANCES'],**props)
    rows=evaluate_batch_platform_guard(linked_design(r),r)
    assert rows[-1]['verdict']==('PASS' if case=='valid' else 'NEEDS_REVIEW' if case=='unknown' else 'FAIL')
