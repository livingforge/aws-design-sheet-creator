import pytest
from aws_design_sheet.checks.emrserverless.worker_sizes import evaluate_emrserverless_worker_sizes
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('cpu,mem,expected',[(1,1,'FAIL'),(1,2,'PASS'),(1,8,'PASS'),(1,9,'FAIL'),(2,4,'PASS'),(2,16,'PASS'),(2,17,'FAIL'),(4,8,'PASS'),(4,30,'PASS'),(4,31,'FAIL'),(8,16,'PASS'),(8,17,'FAIL'),(8,60,'PASS'),(8,64,'FAIL'),(16,32,'PASS'),(16,36,'FAIL'),(16,120,'PASS'),(16,128,'FAIL'),(32,60,'PASS'),(32,120,'PASS'),(32,244,'PASS'),(32,128,'FAIL'),(3,8,'NEEDS_REVIEW')])
@pytest.mark.parametrize('units',[True,False])
def test_worker_memory(cpu,mem,expected,units):
    config={'Cpu':str(cpu)+(' vCPU' if units else ''),'Memory':str(mem)+(' GB' if units else '')}
    r=target('main','AWS::EMRServerless::Application',InitialCapacity=[{'Value':{'WorkerConfiguration':config}}])
    assert evaluate_emrserverless_worker_sizes(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('disk,expected',[('19GB','FAIL'),('20GB','PASS'),('200 GB','PASS'),('201gb','FAIL'),('20','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
@pytest.mark.parametrize('kind',[None,'STANDARD','SHUFFLE_OPTIMIZED',UNKNOWN])
def test_worker_disk(disk,expected,kind):
    config={'Cpu':'2','Memory':'8','Disk':disk}
    if kind is not None:config['DiskType']=kind
    r=target('main','AWS::EMRServerless::Application',InitialCapacity=[{'Value':{'WorkerConfiguration':config}}])
    f=next(f for f in evaluate_emrserverless_worker_sizes(linked_design(r),r) if f['path'].endswith('/Disk'))
    assert f['verdict']==(expected if kind is None or kind=='STANDARD' else 'NEEDS_REVIEW')


def test_cumulative_maximum_is_not_a_worker_size():
    r=target('main','AWS::EMRServerless::Application',MaximumCapacity={'Cpu':'400vCPU','Memory':'1024GB','Disk':'1000GB'})
    assert evaluate_emrserverless_worker_sizes(linked_design(r),r)==[]


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::EMRServerless::Application',InitialCapacity=[{'Value':{'WorkerConfiguration':{'Cpu':'8vCPU','Memory':'17GB'}}}])
    assert any(f['rule_id']=='EMRSERVERLESS_INITIAL_WORKER_SIZES' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
