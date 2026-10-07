import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.fsx.ha_capacity import evaluate_fsx_ha_capacity
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(props):
    r=target('main','AWS::FSx::FileSystem',FileSystemType='ONTAP',**props)
    return {f['rule_id']:f['verdict'] for f in evaluate_fsx_ha_capacity(linked_design(r),r)}


@pytest.mark.parametrize('pairs',[1,2,3,6,12])
@pytest.mark.parametrize('where',['below','low','high','above'])
def test_storage_bounds(pairs,where):
    low=1024*pairs;high=min(524288*pairs,1048576)
    size={'below':low-1,'low':low,'high':high,'above':high+1}[where]
    assert check({'StorageCapacity':size,'OntapConfiguration':{'HAPairs':pairs}})['FSX_ONTAP_HA_STORAGE']==('PASS' if where in ('low','high') else 'FAIL')


@pytest.mark.parametrize('pairs,size,expected',[(UNKNOWN,2048,'NEEDS_REVIEW'),(True,2048,'NEEDS_REVIEW'),(0,2048,'NEEDS_REVIEW'),(13,2048,'NEEDS_REVIEW'),(2,UNKNOWN,'NEEDS_REVIEW'),(2,True,'NEEDS_REVIEW')])
def test_unresolved_storage(pairs,size,expected):
    assert check({'StorageCapacity':size,'OntapConfiguration':{'HAPairs':pairs}})['FSX_ONTAP_HA_STORAGE']==expected


@pytest.mark.parametrize('deployment,pairs,capacity,expected',[
    ('SINGLE_AZ_2',1,384,'PASS'),('SINGLE_AZ_2',1,768,'PASS'),
    ('SINGLE_AZ_2',2,768,'FAIL'),('SINGLE_AZ_2',2,1536,'FAIL'),
    ('SINGLE_AZ_2',2,3072,'PASS'),('SINGLE_AZ_2',12,73728,'PASS'),
    ('SINGLE_AZ_2',2,3073,'FAIL'),('SINGLE_AZ_2',2,0,'FAIL'),
    ('MULTI_AZ_1',1,128,'PASS'),('MULTI_AZ_1',1,384,'FAIL'),
    ('SINGLE_AZ_1',1,4096,'PASS'),('SINGLE_AZ_1',1,6144,'FAIL'),
    ('MULTI_AZ_2',1,384,'PASS'),('MULTI_AZ_2',1,6144,'PASS'),
    ('MULTI_AZ_2',2,3072,'NEEDS_REVIEW'),('OTHER',1,1536,'NEEDS_REVIEW'),
])
def test_total_throughput(deployment,pairs,capacity,expected):
    assert check({'OntapConfiguration':{'DeploymentType':deployment,'HAPairs':pairs,'ThroughputCapacity':capacity}})['FSX_ONTAP_HA_THROUGHPUT']==expected


@pytest.mark.parametrize('pairs,per,expected',[(1,384,'PASS'),(2,384,'FAIL'),(12,1536,'PASS'),(12,6144,'PASS'),(2,3073,'FAIL'),(UNKNOWN,1536,'NEEDS_REVIEW')])
def test_per_pair_throughput(pairs,per,expected):
    assert check({'OntapConfiguration':{'DeploymentType':'SINGLE_AZ_2','HAPairs':pairs,'ThroughputCapacityPerHAPair':per}})['FSX_ONTAP_HA_THROUGHPUT']==expected


@pytest.mark.parametrize('mode',['default_pairs','both_fields','unknown_parent','template','missing_storage'])
def test_defaults_and_ambiguity(mode):
    props={'StorageCapacity':1024,'OntapConfiguration':{'DeploymentType':'SINGLE_AZ_2','ThroughputCapacity':384}}
    if mode=='both_fields':props['OntapConfiguration']['ThroughputCapacityPerHAPair']=384
    if mode=='unknown_parent':props['OntapConfiguration']=UNKNOWN
    if mode=='missing_storage':props.pop('StorageCapacity')
    r=target('main','AWS::FSx::FileSystem',FileSystemType='ONTAP',**props)
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    found={f['rule_id']:f['verdict'] for f in evaluate_fsx_ha_capacity(linked_design(r),r)}
    assert found['FSX_ONTAP_HA_STORAGE']==('NEEDS_REVIEW' if mode in ('unknown_parent','template','missing_storage') else 'PASS')
    assert found['FSX_ONTAP_HA_THROUGHPUT']==('NEEDS_REVIEW' if mode in ('unknown_parent','template','both_fields') else 'PASS')


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::FSx::FileSystem',FileSystemType='ONTAP',StorageCapacity=1024,OntapConfiguration={'HAPairs':2})
    assert any(f['rule_id']=='FSX_ONTAP_HA_STORAGE' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
