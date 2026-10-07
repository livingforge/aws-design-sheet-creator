import pytest
from aws_design_sheet.checks.appsync.channel_and_function import evaluate_appsync_channel_and_function
from aws_design_sheet.checks.batch.job_queue_and_definition import evaluate_batch_job_queue_and_definition
from aws_design_sheet.checks.registry import combine
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
containers_checks=combine(evaluate_appsync_channel_and_function,evaluate_batch_job_queue_and_definition)


def result(rule,platform,task,nested=False):
    ecs={'TaskProperties':[task]}
    props={'NodeProperties':{'NodeRangeProperties':[{'EcsProperties':ecs}]}} if nested else {'EcsProperties':ecs}
    r=target('job','AWS::Batch::JobDefinition',PlatformCapabilities=platform,**props)
    return [f for f in containers_checks(linked_design(r),r) if f['rule_id']==rule]


@pytest.mark.parametrize('nested',[False,True])
@pytest.mark.parametrize('task,expected',[({},'FAIL'),({'ExecutionRoleArn':'arn:aws:iam::123456789012:role/task'},'PASS'),
    ({'ExecutionRoleArn':UNKNOWN},'NEEDS_REVIEW')])
def test_execution_role(task,expected,nested):
    assert result('BATCH_TASK_FARGATE_ROLE',['FARGATE'],task,nested)[0]['verdict']==expected


@pytest.mark.parametrize('platform',[UNKNOWN,[],['FARGATE','EC2'],['FUTURE']])
def test_platform_ambiguity(platform):
    assert result('BATCH_TASK_FARGATE_ROLE',platform,{})[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('platform,key,expected',[
    ('FARGATE','IpcMode','FAIL'),('EC2','IpcMode','PASS'),('EC2','NetworkConfiguration','FAIL'),
    ('MANAGED_INSTANCES','NetworkConfiguration','FAIL'),('FARGATE','NetworkConfiguration','PASS'),
    ('EC2','NetworkMode','FAIL'),('FARGATE','NetworkMode','FAIL'),('MANAGED_INSTANCES','NetworkMode','PASS')])
def test_platform_fields(platform,key,expected):
    assert result('BATCH_TASK_PLATFORM_FIELDS',[platform],{key:'value'})[0]['verdict']==expected


@pytest.mark.parametrize('key',['StartTimeout','StopTimeout'])
@pytest.mark.parametrize('value,expected',[(120,'PASS'),(121,'FAIL'),(UNKNOWN,'NEEDS_REVIEW'),(True,'NEEDS_REVIEW')])
def test_timeout(key,value,expected):
    assert result('BATCH_TASK_FARGATE_TIMEOUT',['FARGATE'],{'Containers':[{key:value}]})[0]['verdict']==expected


@pytest.mark.parametrize('handler',['OnPublish','OnSubscribe'])
@pytest.mark.parametrize('other_api,expected',[('api1','PASS'),('api2','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_handler_api(handler,other_api,expected):
    r=target('namespace','AWS::AppSync::ChannelNamespace',ApiId='api1',Name='name',
             HandlerConfigs={handler:{'Integration':{'DataSourceName':'source'}}})
    source=target('source','AWS::AppSync::DataSource',ApiId=other_api)
    d=linked_design(r,[source],[('HandlerConfigs/'+handler+'/Integration/DataSourceName','source')])
    assert next(f for f in containers_checks(d,r) if f['rule_id']=='APPSYNC_HANDLER_DATASOURCE_API')['verdict']==expected
