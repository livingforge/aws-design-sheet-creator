import pytest
from aws_design_sheet.checks.pipes.task_context import evaluate_pipes_task_context
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('mode',['awsvpc','bridge','host','none',None,UNKNOWN,'future'])
@pytest.mark.parametrize('config',[None,{},UNKNOWN])
def test_network_mode(mode,config):
    params={'TaskDefinitionArn':'task'}
    if config is not None:params['NetworkConfiguration']=config
    r=target('main','AWS::Pipes::Pipe',TargetParameters={'EcsTaskParameters':params})
    t=target('task','AWS::ECS::TaskDefinition',**({} if mode is None else {'NetworkMode':mode}))
    d=linked_design(r,[t],[('TargetParameters/EcsTaskParameters/TaskDefinitionArn','task')])
    expected='NEEDS_REVIEW'
    if config is None and mode=='awsvpc':expected='FAIL'
    elif config is None and (mode is None or mode in ('bridge','host','none')):expected='NOT_APPLICABLE'
    elif config=={} and mode=='awsvpc':expected='PASS'
    elif config=={} and (mode is None or mode in ('bridge','host','none')):expected='FAIL'
    assert evaluate_pipes_task_context(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('case',['member','missing','duplicate','unknown','external','conditional','scope','gpu','dynamic'])
def test_resource_device(case):
    params={'TaskDefinitionArn':'task','Overrides':{'ContainerOverrides':[{'ResourceRequirements':[{'Type':'GPU' if case=='gpu' else 'InferenceAccelerator','Value':'$.device' if case=='dynamic' else 'device'}]}]}}
    r=target('main','AWS::Pipes::Pipe',TargetParameters={'EcsTaskParameters':params})
    devices=[{'DeviceName':UNKNOWN}] if case=='unknown' else [] if case=='missing' else [{'DeviceName':'device'}]*(2 if case=='duplicate' else 1)
    t=target('task','AWS::ECS::TaskDefinition',InferenceAccelerators=devices)
    d=linked_design(r,[t])
    if case!='external':link(d,r,'TargetParameters/EcsTaskParameters/TaskDefinitionArn',t)
    if case=='conditional':d.relations[-1].condition='maybe'
    if case=='scope':t.scope.account='222222222222'
    rows=[f for f in evaluate_pipes_task_context(d,r) if f['rule_id']=='PIPES_RESOURCE_ACCELERATOR_MEMBER']
    if case=='gpu':assert not rows
    else:assert rows[0]['verdict']==('PASS' if case=='member' else 'FAIL' if case=='missing' else 'NEEDS_REVIEW')
