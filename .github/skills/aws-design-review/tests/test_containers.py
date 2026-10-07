import pytest
from aws_design_sheet.checks.appsync.channel_and_function import evaluate_appsync_channel_and_function
from aws_design_sheet.checks.batch.job_queue_and_definition import evaluate_batch_job_queue_and_definition
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.models import Relation
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
containers_checks=combine(evaluate_appsync_channel_and_function,evaluate_batch_job_queue_and_definition)


def findings(rule,**props):
    r=target('job','AWS::Batch::JobDefinition',**props)
    return [f for f in containers_checks(linked_design(r),r) if f['rule_id']==rule]


@pytest.mark.parametrize('a,b,expected',[('api1','api1','PASS'),('api1','api2','FAIL'),(UNKNOWN,'api1','NEEDS_REVIEW')])
@pytest.mark.parametrize('conditional',[False,True])
def test_api_literals(a,b,expected,conditional):
    r=target('function','AWS::AppSync::FunctionConfiguration',ApiId=a,DataSourceName='source')
    source=target('source','AWS::AppSync::DataSource',ApiId=b)
    d=linked_design(r,[source],[('DataSourceName','source')])
    if conditional:d.relations[0].condition='condition'
    assert containers_checks(d,r)[0]['verdict']==('NEEDS_REVIEW' if conditional else expected)


@pytest.mark.parametrize('same,expected',[(True,'PASS'),(False,'FAIL')])
def test_api_resource_identity(same,expected):
    r=target('function','AWS::AppSync::FunctionConfiguration',ApiId='api',DataSourceName='source')
    source=target('source','AWS::AppSync::DataSource',ApiId='api')
    a=target('a','AWS::AppSync::GraphQLApi');b=target('b',a.type)
    d=linked_design(r,[source,a,b],[('DataSourceName','source'),('ApiId','a')])
    d.relations.append(Relation(id='other',source_resource_id='source',source_path='/properties/ApiId',target_resource_id='a' if same else 'b'))
    assert containers_checks(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('nested',[False,True])
@pytest.mark.parametrize('containers,expected',[([{'Essential':False}],'FAIL'),([{}],'PASS'),
    ([{'Essential':UNKNOWN}],'NEEDS_REVIEW'),([UNKNOWN],'NEEDS_REVIEW'),
    ([{'Essential':False},{'Essential':True}],'PASS'),([],'FAIL')])
def test_essential(containers,expected,nested):
    ecs={'TaskProperties':[{'Containers':containers}]}
    props={'NodeProperties':{'NodeRangeProperties':[{'EcsProperties':ecs}]}} if nested else {'EcsProperties':ecs}
    assert findings('BATCH_TASK_ESSENTIAL',**props)[0]['verdict']==expected


@pytest.mark.parametrize('condition',['COMPLETE','SUCCESS'])
@pytest.mark.parametrize('flag,expected',[(True,'FAIL'),(False,'PASS'),(UNKNOWN,'NEEDS_REVIEW')])
def test_dependency(condition,flag,expected):
    containers=[{'Name':'main','DependsOn':[{'Condition':condition,'ContainerName':'side'}]},
                {'Name':'side','Essential':flag}]
    assert findings('BATCH_TASK_DEPENDENCY_ESSENTIAL',EcsProperties={'TaskProperties':[{'Containers':containers}]})[0]['verdict']==expected


@pytest.mark.parametrize('containers,expected',[([{},{}],'FAIL'),([{'Name':'a'},{'Name':'b'}],'PASS'),
    ([{'Name':'a'},UNKNOWN],'NEEDS_REVIEW')])
def test_eks_names(containers,expected):
    assert findings('BATCH_EKS_CONTAINER_NAMES',EksProperties={'PodProperties':{'Containers':containers}})[0]['verdict']==expected


def test_eks_init_name_collision():
    assert findings('BATCH_EKS_CONTAINER_NAMES',EksProperties={'PodProperties':{
        'Containers':[{'Name':'a'}],'InitContainers':[{'Name':'a'}]}})[0]['verdict']=='FAIL'


@pytest.mark.parametrize('ranges,expected',[(['0:3'],'PASS'),([':'],'PASS'),(['0:1','2:'],'PASS'),
    (['0:3','1:2'],'PASS'),(['0','2:3'],'FAIL'),(['0:1',UNKNOWN],'NEEDS_REVIEW'),
    (['0:3',UNKNOWN],'PASS'),(['0:4'],'NEEDS_REVIEW'),(['3:1'],'NEEDS_REVIEW')])
def test_node_coverage(ranges,expected):
    assert findings('BATCH_NODE_RANGE_COVERAGE',NodeProperties={'NumNodes':4,'NodeRangeProperties':[
        {'TargetNodes':r} for r in ranges]})[0]['verdict']==expected


@pytest.mark.parametrize('init',[False,True])
@pytest.mark.parametrize('quantity,limits,requests,expected',[
    ('memory','1024Mi','1024Mi','PASS'),('memory','1024Mi','512Mi','FAIL'),
    ('memory','1Gi','1024Mi','NEEDS_REVIEW'),('memory',UNKNOWN,'512Mi','NEEDS_REVIEW'),
    ('cpu','0.5','.50','PASS'),('cpu','0.25','0.5','FAIL'),('cpu','1','0.5','PASS'),
    ('cpu','500m','0.5','NEEDS_REVIEW'),('cpu','NaN','1','NEEDS_REVIEW')])
def test_eks_resource_pairs(init,quantity,limits,requests,expected):
    container={'Resources':{'Limits':{quantity:limits},'Requests':{quantity:requests}}}
    assert findings('BATCH_EKS_RESOURCE_PAIR',EksProperties={'PodProperties':{
        'InitContainers' if init else 'Containers':[container]}})[0]['verdict']==expected


@pytest.mark.parametrize('names,expected',[(['team','team'],'PASS'),(['team','other'],'FAIL'),
    (['team',UNKNOWN],'NEEDS_REVIEW'),(['team',None],'NEEDS_REVIEW'),
    (['team','other',UNKNOWN],'FAIL')])
def test_node_namespace(names,expected):
    assert findings('BATCH_EKS_NODE_NAMESPACE',NodeProperties={'NodeRangeProperties':[
        {'EksProperties':{'PodProperties':{'Metadata':{} if n is None else {'Namespace':n}}}}
        for n in names]})[0]['verdict']==expected


def test_checker_integration():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('job','AWS::Batch::JobDefinition',EcsProperties={'TaskProperties':[
        {'Containers':[{'Essential':False}]}]})
    checked=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    row=next(f for f in checked['results'] if f['rule_id']=='BATCH_TASK_ESSENTIAL')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']


@pytest.mark.parametrize('kinds,expected',[(['EC2','SPOT'],'PASS'),(['FARGATE','FARGATE_SPOT'],'PASS'),
    (['EC2','FARGATE'],'FAIL'),(['EC2',UNKNOWN],'NEEDS_REVIEW'),
    (['EC2','FARGATE',UNKNOWN],'FAIL'),(['MANAGED_INSTANCES'],'NEEDS_REVIEW')])
def test_queue_family(kinds,expected):
    r=target('queue','AWS::Batch::JobQueue',ComputeEnvironmentOrder=[{'ComputeEnvironment':str(i)} for i in range(len(kinds))])
    targets=[target(str(i),'AWS::Batch::ComputeEnvironment',ComputeResources={'Type':kind}) for i,kind in enumerate(kinds)]
    d=linked_design(r,targets,[('ComputeEnvironmentOrder/'+str(i)+'/ComputeEnvironment',str(i)) for i in range(len(kinds))])
    assert containers_checks(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('kind,action,expected',[
    ('ECS','CANCEL','PASS'),('EKS','TERMINATE','FAIL'),('ECS_FARGATE','CANCEL','PASS'),
    ('SAGEMAKER_TRAINING','TERMINATE','PASS'),('SAGEMAKER_TRAINING','CANCEL','FAIL'),
    ('ECS_MANAGED_INSTANCES','CANCEL','NEEDS_REVIEW'),(UNKNOWN,'CANCEL','NEEDS_REVIEW'),
    ('ECS',UNKNOWN,'NEEDS_REVIEW')])
def test_queue_action(kind,action,expected):
    r=target('queue','AWS::Batch::JobQueue',JobQueueType=kind,JobStateTimeLimitActions=[{'Action':action}])
    assert containers_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('api,name,expected',[('api1','same','FAIL'),('api2','same','PASS'),
    ('api1','different','PASS'),(UNKNOWN,'same','NEEDS_REVIEW'),('api1',UNKNOWN,'NEEDS_REVIEW')])
def test_channel_names(api,name,expected):
    r=target('one','AWS::AppSync::ChannelNamespace',ApiId='api1',Name='same')
    other=target('two',r.type,ApiId=api,Name=name)
    assert containers_checks(linked_design(r,[other]),r)[0]['verdict']==expected


def test_channel_linked_api():
    r=target('one','AWS::AppSync::ChannelNamespace',Name='same',ApiId='api')
    other=target('two',r.type,Name='same',ApiId='api')
    api=target('api','AWS::AppSync::Api')
    d=linked_design(r,[other,api],[('ApiId','api')])
    d.relations.append(Relation(id='other',source_resource_id='two',source_path='/properties/ApiId',target_resource_id='api'))
    assert containers_checks(d,r)[0]['verdict']=='FAIL'
    d.relations[-1].condition='conditional'
    assert containers_checks(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_unknown_scope_not_a_collision():
    r=target('one','AWS::AppSync::ChannelNamespace',ApiId='api1',Name='same')
    other=target('two',r.type,ApiId='api1',Name='same')
    r.scope.account=other.scope.account='unknown'
    assert containers_checks(linked_design(r,[other]),r)[0]['verdict']=='NEEDS_REVIEW'
