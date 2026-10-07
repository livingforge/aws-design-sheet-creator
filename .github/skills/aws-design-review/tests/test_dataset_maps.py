from pathlib import Path
import pytest
from aws_design_sheet.checks.quicksight.data_set import evaluate_quicksight_data_set
from aws_design_sheet.checks.pipes.batch_instance_applicability import evaluate_pipes_batch_instance_applicability
from aws_design_sheet.checks.registry import combine
dataset_maps_checks = combine(evaluate_quicksight_data_set, evaluate_pipes_batch_instance_applicability)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('raw,verdict',[
    ({'S3Source':{}},'PASS'),({'SaaSTable':{}},'PASS'),
    ({'S3Source':{},'CustomSql':{}},'FAIL'),
    ({'S3Source':{},'CustomSql':UNKNOWN},'NEEDS_REVIEW'),
    ({'S3Source':{},'CustomSql':{},'RelationalTable':UNKNOWN},'FAIL'),
    ({'S3Source':None,'CustomSql':{}},'PASS'),({},'NEEDS_REVIEW'),
    (UNKNOWN,'NEEDS_REVIEW'),({'S3Source':'invalid'},'NEEDS_REVIEW'),
])
def test_physical(raw,verdict):
    r=target('main','AWS::QuickSight::DataSet',PhysicalTableMap={'table':raw})
    f=dataset_maps_checks(linked_design(r),r)[0]
    assert f['verdict']==verdict


@pytest.mark.parametrize('raw,verdict',[
    ({'a':{'Columns':['x']},'b':{'Columns':['y']}},'PASS'),
    ({'a':{'Columns':['x']},'b':{'Columns':['x']}},'FAIL'),
    ({'a':{'Columns':['x','x']}},'PASS'),
    ({'a/b':{'Columns':['x']},'c~d':{'Columns':['x']}},'NEEDS_REVIEW'),
    ({'a':{'Columns':['x']},'b':{'Columns':[UNKNOWN]}},'NEEDS_REVIEW'),
    ({'a':{'Columns':['x']},'b':{'Columns':['x',UNKNOWN]}},'FAIL'),
    ({'a':UNKNOWN},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),
    ({'a':{}},'PASS'),({},'PASS'),({'a':{'Columns':['${column}']}},'NEEDS_REVIEW'),
])
def test_folders(raw,verdict):
    r=target('main','AWS::QuickSight::DataSet',FieldFolders=raw)
    assert dataset_maps_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('case',['pass','container','fargate','unknown','default','external','conditional','duplicate','dynamic','wrong_type'])
def test_batch(case):
    r=target('main','AWS::Pipes::Pipe',TargetParameters={'BatchJobParameters':{'JobDefinition':'job','ContainerOverrides':{'InstanceType':'${instance}' if case=='dynamic' else 'm5.large'}}})
    props={'Type':'container' if case=='container' else UNKNOWN if case=='unknown' else 'multinode'}
    if case!='default':props['PlatformCapabilities']=['FARGATE' if case=='fargate' else 'EC2']
    t=target('job','AWS::S3::Bucket' if case=='wrong_type' else 'AWS::Batch::JobDefinition',**props)
    links=[] if case=='external' else [('TargetParameters/BatchJobParameters/JobDefinition','job')]
    if case=='duplicate':links+=links
    d=linked_design(r,[t],links)
    if case=='conditional':d.relations[0].condition='condition'
    assert dataset_maps_checks(d,r)[0]['verdict']==('PASS' if case in ('pass','default') else 'FAIL' if case in ('container','fargate') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::QuickSight::DataSet','AWS::Pipes::Pipe'])
def test_absent(kind):
    r=target('main',kind);assert not dataset_maps_checks(linked_design(r),r)


def test_checker():
    r=target('main','AWS::QuickSight::DataSet',FieldFolders={'a':{'Columns':['x']},'b':{'Columns':['x']}})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='QUICKSIGHT_FIELD_FOLDER_UNIQUE' and f['verdict']=='FAIL' for f in results)
