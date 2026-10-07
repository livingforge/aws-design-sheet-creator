from pathlib import Path
import pytest
from aws_design_sheet.checks.fsx.file_system import evaluate_fsx_file_system
from aws_design_sheet.checks.gamelift.container_group_definition import evaluate_gamelift_container_group_definition
from aws_design_sheet.checks.glue.job_arguments import evaluate_glue_job_arguments
from aws_design_sheet.checks.registry import combine
allocations_checks = combine(evaluate_fsx_file_system, evaluate_gamelift_container_group_definition, evaluate_glue_job_arguments)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,rule,**props):
    r=target('subject','AWS::'+kind,**props)
    return [row for row in allocations_checks(linked_design(r),r) if row['rule_id']==rule]


@pytest.mark.parametrize('imported,exported,expected',[
    ('s3://bucket/in','s3://bucket/out','PASS'),('s3://bucket','s3://other/out','FAIL'),
    ('s3://bucket.one/a','s3://bucket.one/b','PASS'),(UNKNOWN,'s3://bucket','NEEDS_REVIEW'),
    ('s3://bucket','s3://${Bucket}/out','NEEDS_REVIEW'),('https://bucket','s3://bucket','NEEDS_REVIEW'),
    ('s3://bucket','s3://bucket-other','FAIL')])
def test_lustre_buckets(imported,exported,expected):
    assert check('FSx::FileSystem','FSX_LUSTRE_BUCKET',LustreConfiguration={'ImportPath':imported,'ExportPath':exported})[0]['verdict']==expected


@pytest.mark.parametrize('alias,expected',[
    ('ACCOUNT_1.example.com','PASS'),('1-name.example','PASS'),('-name.example','FAIL'),
    ('name.example-','FAIL'),('name..example','FAIL'),('name','FAIL'),('a b.example','FAIL'),
    ('name.-example','NEEDS_REVIEW'),('name.example.','NEEDS_REVIEW'),('名前.example','NEEDS_REVIEW'),
    (UNKNOWN,'NEEDS_REVIEW'),('${Alias}','NEEDS_REVIEW')])
def test_aliases(alias,expected):
    assert check('FSx::FileSystem','FSX_WINDOWS_ALIASES',WindowsConfiguration={'Aliases':[alias]})[0]['verdict']==expected


@pytest.mark.parametrize('n,expected',[(4000,'PASS'),(8000,'PASS'),(4001,'FAIL'),(0,'FAIL'),(True,'NEEDS_REVIEW'),('8000','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_throughput(n,expected):
    assert check('FSx::FileSystem','FSX_LUSTRE_THROUGHPUT_MULTIPLE',StorageType='INTELLIGENT_TIERING',LustreConfiguration={'ThroughputCapacity':n})[0]['verdict']==expected


@pytest.mark.parametrize('total,containers,expected',[
    (0.3,[{'Vcpu':0.1},{'Vcpu':0.2}],'PASS'),(0.29,[{'Vcpu':0.1},{'Vcpu':0.2}],'FAIL'),
    (2,[{'Vcpu':3},UNKNOWN],'FAIL'),(3,[{'Vcpu':2},UNKNOWN],'NEEDS_REVIEW'),
    (1,[{},{}],'PASS'),(1,[{'Vcpu':True}],'NEEDS_REVIEW'),(1,UNKNOWN,'NEEDS_REVIEW'),
    (UNKNOWN,[{'Vcpu':2}],'NEEDS_REVIEW'),(1,[{'Vcpu':'2'}],'NEEDS_REVIEW')])
def test_cpu(total,containers,expected):
    assert check('GameLift::ContainerGroupDefinition','GAMELIFT_CPU_SUM',TotalVcpuLimit=total,SupportContainerDefinitions=containers)[0]['verdict']==expected


def test_inherited_cpu_and_names_held():
    for rule in ('GAMELIFT_CPU_SUM','GAMELIFT_CONTAINER_NAMES'):
        assert check('GameLift::ContainerGroupDefinition',rule,SourceVersionNumber=1,TotalVcpuLimit=1,SupportContainerDefinitions=[{'Vcpu':2}])[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('game,support,expected',[
    ('server',['helper'],'PASS'),('server',['server'],'FAIL'),('server',['one','one'],'FAIL'),
    (UNKNOWN,['helper'],'NEEDS_REVIEW'),('server',['server',UNKNOWN],'FAIL')])
def test_container_names(game,support,expected):
    assert check('GameLift::ContainerGroupDefinition','GAMELIFT_CONTAINER_NAMES',GameServerContainerDefinition={'ContainerName':game},SupportContainerDefinitions=[{'ContainerName':x} for x in support])[0]['verdict']==expected


@pytest.mark.parametrize('a,b,p,expected',[(20,30,'TCP','FAIL'),(21,30,'TCP','PASS'),(10,20,'UDP','PASS'),(15,16,'TCP','FAIL'),(30,20,'TCP','NEEDS_REVIEW'),(20,30,UNKNOWN,'NEEDS_REVIEW')])
@pytest.mark.parametrize('support',[False,True])
def test_port_ranges(a,b,p,expected,support):
    container={'PortConfiguration':{'ContainerPortRanges':[{'FromPort':10,'ToPort':20,'Protocol':'TCP'},{'FromPort':a,'ToPort':b,'Protocol':p}]}}
    props={'SupportContainerDefinitions':[container]} if support else {'GameServerContainerDefinition':container}
    assert check('GameLift::ContainerGroupDefinition','GAMELIFT_PORT_OVERLAP',**props)[0]['verdict']==expected


@pytest.mark.parametrize('condition,name,essential,expected',[
    ('SUCCESS','server',False,'FAIL'),('COMPLETE','helper',True,'FAIL'),('SUCCESS','helper',False,'PASS'),
    ('SUCCESS','helper',UNKNOWN,'NEEDS_REVIEW'),('START','server',True,'NOT_APPLICABLE'),
    ('COMPLETE','external',False,'NEEDS_REVIEW')])
def test_dependency(condition,name,essential,expected):
    assert check('GameLift::ContainerGroupDefinition','GAMELIFT_DEPENDENCY_ESSENTIAL',GameServerContainerDefinition={'ContainerName':'server','DependsOn':[{'Condition':condition,'ContainerName':name}]},SupportContainerDefinitions=[{'ContainerName':'helper','Essential':essential}])[0]['verdict']==expected


@pytest.mark.parametrize('args,expected',[
    ({'GLUE_PYTHON_VERSION':'3'},'PASS'),({'GLUE_PYTHON_VERSION':'2','--enable-glue-datacatalog':''},'PASS'),
    ({'GLUE_PYTHON_VERSION':'3.9'},'FAIL'),({'GLUE_PYTHON_VERSION':3},'NEEDS_REVIEW'),
    ({'GLUE_PYTHON_VERSION':UNKNOWN},'NEEDS_REVIEW'),({'--unknown':'x'},'FAIL'),
    ({'--enable-glue-datacatalog':'true'},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),({},'PASS')])
def test_glue_arguments(args,expected):
    assert check('Glue::DevEndpoint','GLUE_ENDPOINT_ARGUMENTS',Arguments=args)[0]['verdict']==expected


@pytest.mark.parametrize('command,n,expected',[
    ('glueetl',2,'PASS'),('glueetl',2.0,'PASS'),('glueetl',2.5,'FAIL'),('glueetl',True,'NEEDS_REVIEW'),
    ('glueetl','2.5','NEEDS_REVIEW'),('pythonshell',0.0625,'NOT_APPLICABLE'),(UNKNOWN,2.5,'NEEDS_REVIEW')])
def test_glue_integral(command,n,expected):
    assert check('Glue::Job','GLUE_JOB_INTEGER_DPU',Command={'Name':command},MaxCapacity=n)[0]['verdict']==expected


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::GameLift::ContainerGroupDefinition',TotalVcpuLimit=1,SupportContainerDefinitions=[{'Vcpu':2}])
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    row=next(x for x in result['results'] if x['rule_id']=='GAMELIFT_CPU_SUM')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
