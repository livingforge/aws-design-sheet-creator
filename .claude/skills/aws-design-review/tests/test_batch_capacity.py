import pytest
from aws_design_sheet.checks.batch.capacity import evaluate_batch_capacity
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def run(rule,**props):
    r=target('job','AWS::Batch::JobDefinition',**props)
    return [f for f in evaluate_batch_capacity(linked_design(r),r) if f['rule_id']==rule]


@pytest.mark.parametrize('cpu,memory,expected',[
    ('0.25','512','PASS'),('0.25','3072','FAIL'),('0.5','4096','PASS'),('1','8192','PASS'),
    ('2','16384','PASS'),('2','17408','FAIL'),('4','30720','PASS'),('4','32768','FAIL'),
    ('8','16384','PASS'),('8','61440','PASS'),('8','17408','FAIL'),
    ('16','122880','PASS'),('16','61440','FAIL'),('32','61440','PASS'),('32','249856','PASS'),
    ('32','65536','FAIL'),('0.75','2048','FAIL'),('3','4096','FAIL'),
    ('1.0','2048','NEEDS_REVIEW'),('1',UNKNOWN,'NEEDS_REVIEW'),(UNKNOWN,'2048','NEEDS_REVIEW')])
def test_fargate_pair(cpu,memory,expected):
    assert run('BATCH_FARGATE_RESOURCE_PAIR',PlatformCapabilities=['FARGATE'],ContainerProperties={
        'ResourceRequirements':[{'Type':'VCPU','Value':cpu},{'Type':'MEMORY','Value':memory}]})[0]['verdict']==expected


@pytest.mark.parametrize('requirements,expected',[(None,'FAIL'),([],'FAIL'),
    ([{'Type':'VCPU','Value':'1'}],'FAIL'),
    ([{'Type':'VCPU','Value':'1'},{'Type':'VCPU','Value':'1'}],'NEEDS_REVIEW'),
    ([UNKNOWN],'NEEDS_REVIEW')])
def test_incomplete_requirements(requirements,expected):
    container={} if requirements is None else {'ResourceRequirements':requirements}
    assert run('BATCH_FARGATE_RESOURCE_PAIR',PlatformCapabilities=['FARGATE'],ContainerProperties=container)[0]['verdict']==expected


@pytest.mark.parametrize('kind,expected',[('GPU','FAIL'),('MEMORY','PASS'),(UNKNOWN,'NEEDS_REVIEW')])
def test_fargate_gpu(kind,expected):
    assert run('BATCH_FARGATE_GPU',PlatformCapabilities=['FARGATE'],EcsProperties={'TaskProperties':[
        {'Containers':[{'ResourceRequirements':[{'Type':kind,'Value':UNKNOWN}]}]}]})[0]['verdict']==expected


@pytest.mark.parametrize('key,val,expected',[('MaxSwap',0,'PASS'),('MaxSwap',-1,'FAIL'),
    ('Swappiness',100,'PASS'),('Swappiness',101,'FAIL'),('Swappiness',True,'NEEDS_REVIEW')])
def test_nested_linux_values(key,val,expected):
    assert run('BATCH_NESTED_NUMERIC',EcsProperties={'TaskProperties':[
        {'Containers':[{'LinuxParameters':{key:val}}]}]})[0]['verdict']==expected


@pytest.mark.parametrize('val,expected',[(20,'FAIL'),(21,'PASS'),(200,'PASS'),(201,'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_task_storage(val,expected):
    assert run('BATCH_NESTED_NUMERIC',EcsProperties={'TaskProperties':[{'EphemeralStorage':{'SizeInGiB':val}}]})[0]['verdict']==expected


@pytest.mark.parametrize('key',['Devices','MaxSwap','SharedMemorySize','Swappiness','Tmpfs'])
def test_fargate_nested_linux(key):
    assert run('BATCH_NESTED_FARGATE_LINUX',PlatformCapabilities=['FARGATE'],EcsProperties={
        'TaskProperties':[{'Containers':[{'LinuxParameters':{key:0}}]}]})[0]['verdict']=='FAIL'


@pytest.mark.parametrize('port,expected',[(0,'PASS'),(65535,'PASS'),(-1,'FAIL'),(65536,'FAIL'),(True,'NEEDS_REVIEW')])
def test_efs_port(port,expected):
    assert run('BATCH_EFS_TRANSIT_PORT',ContainerProperties={'Volumes':[{
        'EfsVolumeConfiguration':{'TransitEncryptionPort':port}}]})[0]['verdict']==expected


@pytest.mark.parametrize('options,expected',[(['ro','nosuid'],'PASS'),(['unknown-option'],'FAIL'),
    (['mode=1777'],'NEEDS_REVIEW'),([UNKNOWN],'NEEDS_REVIEW'),(['ro',UNKNOWN,'bad'],'FAIL')])
def test_tmpfs_options(options,expected):
    assert run('BATCH_TMPFS_OPTIONS',ContainerProperties={'LinuxParameters':{'Tmpfs':[
        {'MountOptions':options}]}})[0]['verdict']==expected
