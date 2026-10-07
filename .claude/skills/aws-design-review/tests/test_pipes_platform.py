import pytest
from aws_design_sheet.checks.pipes.platform import evaluate_pipes_platform
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(os='LINUX',version='1.4.0',launch='FARGATE'):
    r=target('pipe','AWS::Pipes::Pipe',TargetParameters={'EcsTaskParameters':{'LaunchType':launch,'PlatformVersion':version,'Overrides':{'EphemeralStorage':{'SizeInGiB':30},'ContainerOverrides':[{'Name':'app','EnvironmentFiles':[{'Type':'s3','Value':'arn:aws:s3:::bucket/env.env'}]}]}}})
    task=target('task','AWS::ECS::TaskDefinition',RuntimePlatform={'OperatingSystemFamily':os})
    d=linked_design(r,[task]);link(d,r,'TargetParameters/EcsTaskParameters/TaskDefinitionArn',task)
    return d,r,task


def params(r):return r.fields[0].candidates[0].value['EcsTaskParameters']
def verdicts(d,r):return [f['verdict'] for f in evaluate_pipes_platform(d,r)]


@pytest.mark.parametrize('os,version,want',[
    ('LINUX','1.4.0',['PASS']*2),('LINUX','1.3.0',['FAIL']*2),('LINUX','1.10.0',['PASS']*2),
    ('LINUX','LATEST',['NEEDS_REVIEW']*2),('LINUX',UNKNOWN,['NEEDS_REVIEW']*2),
    ('WINDOWS_SERVER_2022_CORE','1.0.0',['PASS','NEEDS_REVIEW']),
    ('WINDOWS_SERVER_2022_CORE','0.9.0',['FAIL','NEEDS_REVIEW']),
    (UNKNOWN,'1.4.0',['NEEDS_REVIEW']*2)])
def test_platform_versions(os,version,want):
    d,r,*_=fixture(os,version);assert verdicts(d,r)==want


@pytest.mark.parametrize('launch,want',[('EC2',['FAIL','NEEDS_REVIEW']),('EXTERNAL',['FAIL','NEEDS_REVIEW']),(UNKNOWN,['NEEDS_REVIEW']*2)])
def test_launch_applicability(launch,want):
    d,r,*_=fixture(launch=launch);assert verdicts(d,r)==want


@pytest.mark.parametrize('names,want',[(['FARGATE'],['PASS']*2),(['FARGATE','FARGATE_SPOT'],['PASS']*2),(['custom'],['NEEDS_REVIEW']*2),([UNKNOWN],['NEEDS_REVIEW']*2)])
def test_capacity_provider_context(names,want):
    d,r,*_=fixture();p=params(r);p.pop('LaunchType');p['CapacityProviderStrategy']=[{'CapacityProvider':n,'Weight':1} for n in names]
    assert verdicts(d,r)==want


@pytest.mark.parametrize('mode',['literal','conditional','missing','scope','unknown_os','unknown_override','launch_and_strategy'])
def test_uncertain_context(mode):
    d,r,task=fixture();p=params(r)
    if mode=='literal':p['TaskDefinitionArn']='arn:aws:ecs:ap-northeast-1:111111111111:task-definition/task:1'
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='missing':d.resources.remove(task)
    if mode=='scope':task.scope.account='222222222222'
    if mode=='unknown_os':task.fields[0].candidates[0].value=UNKNOWN
    if mode=='unknown_override':p['Overrides']=UNKNOWN
    if mode=='launch_and_strategy':p['CapacityProviderStrategy']=[{'CapacityProvider':'FARGATE'}]
    assert verdicts(d,r)==['NEEDS_REVIEW']*2


def test_absent_overrides():
    d,r,*_=fixture();params(r).pop('Overrides')
    assert verdicts(d,r)==['NOT_APPLICABLE']*2


def test_empty_environment_files_not_applicable():
    d,r,*_=fixture();params(r)['Overrides']['ContainerOverrides'][0]['EnvironmentFiles']=[]
    assert verdicts(d,r)==['PASS','NOT_APPLICABLE']


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="PIPES_EPHEMERAL_PLATFORM" and f["verdict"]=="PASS" for f in results)
