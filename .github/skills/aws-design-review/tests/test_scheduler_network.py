import pytest
from aws_design_sheet.checks.scheduler.network import evaluate_scheduler_network, ROOT, VPC
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(mode='awsvpc',config=True):
    ecs={}
    if config:ecs['NetworkConfiguration']={'AwsvpcConfiguration':{'Subnets':['s'],'SecurityGroups':['g']}}
    r=target('schedule','AWS::Scheduler::Schedule',Target={'EcsParameters':ecs})
    task=target('task','AWS::ECS::TaskDefinition',NetworkMode=mode)
    s=target('s','AWS::EC2::Subnet',VpcId='vpc-12345678')
    g=target('g','AWS::EC2::SecurityGroup',VpcId='vpc-12345678')
    d=linked_design(r,[task,s,g]);link(d,r,ROOT.removeprefix('/properties/')+'/TaskDefinitionArn',task)
    if config:
        link(d,r,VPC.removeprefix('/properties/')+'/Subnets/0',s)
        link(d,r,VPC.removeprefix('/properties/')+'/SecurityGroups/0',g)
    return d,r,task,s,g


def verdict(d,r,rule):return next(f['verdict'] for f in evaluate_scheduler_network(d,r) if f['rule_id']=='SCHEDULER_ECS_'+rule)


@pytest.mark.parametrize('mode,config,want',[('awsvpc',True,'PASS'),('awsvpc',False,'FAIL'),('bridge',True,'FAIL'),('bridge',False,'NOT_APPLICABLE'),('host',True,'FAIL'),('none',True,'FAIL'),(UNKNOWN,True,'NEEDS_REVIEW')])
def test_mode(mode,config,want):
    d,r,*_=fixture(mode,config);assert verdict(d,r,'NETWORK_MODE')==want


@pytest.mark.parametrize('case',['different','conditional','external','scope','unknown','default_groups','empty_groups','logical','mixed','conflict'])
def test_vpc(case):
    d,r,t,s,g=fixture();config=r.fields[0].candidates[0].value['EcsParameters']['NetworkConfiguration']['AwsvpcConfiguration']
    want='NEEDS_REVIEW'
    if case=='different':g.fields[0].candidates[0].value='vpc-87654321';want='FAIL'
    if case=='conditional':d.relations[-1].condition='Maybe'
    if case=='external':d.resources.remove(g)
    if case=='scope':g.scope.region='us-east-1'
    if case=='unknown':g.fields[0].candidates[0].value=UNKNOWN
    if case=='default_groups':del config['SecurityGroups'];d.relations.pop();want='PASS'
    if case=='empty_groups':config['SecurityGroups']=[];d.relations.pop()
    if case in ('logical','mixed','conflict'):
        v=target('v','AWS::EC2::VPC');d.resources.append(v);link(d,s,'VpcId',v)
        if case!='conflict':s.fields=[]
        if case=='logical':g.fields=[];link(d,g,'VpcId',v);want='PASS'
    assert verdict(d,r,'VPC_IDENTITY')==want


@pytest.mark.parametrize('case',['literal_task','unknown_config','missing_mode','conditional_task'])
def test_unknown_task_context(case):
    d,r,t,*_=fixture()
    ecs=r.fields[0].candidates[0].value['EcsParameters']
    if case=='literal_task':ecs['TaskDefinitionArn']='arn:aws:ecs:ap-northeast-1:111111111111:task-definition/task:1'
    if case=='unknown_config':ecs['NetworkConfiguration']=UNKNOWN
    if case=='missing_mode':t.fields=[]
    if case=='conditional_task':d.relations[0].condition='Maybe'
    assert verdict(d,r,'NETWORK_MODE')=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='SCHEDULER_ECS_VPC_IDENTITY' and f['verdict']=='PASS' for f in results)
