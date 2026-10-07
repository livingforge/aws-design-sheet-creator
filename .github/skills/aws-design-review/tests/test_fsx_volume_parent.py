import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.fsx.volume_parent import evaluate_fsx_volume_parent
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(size=128,storage='SSD',reservation=10,quota=100):
    r=target('child','AWS::FSx::Volume',VolumeType='OPENZFS',OpenZFSConfiguration={'RecordSizeKiB':size,'StorageCapacityReservationGiB':reservation,'ParentVolumeId':'parent'})
    p=target('parent','AWS::FSx::Volume',VolumeType='OPENZFS',OpenZFSConfiguration={'StorageCapacityQuotaGiB':quota,'ParentVolumeId':'fs'})
    fs=target('fs','AWS::FSx::FileSystem',FileSystemType='OPENZFS',StorageType=storage,StorageCapacity=1000)
    d=linked_design(r,[p,fs],[('OpenZFSConfiguration/ParentVolumeId','parent')]);link(d,p,'OpenZFSConfiguration/ParentVolumeId',fs)
    return d,r,p,fs


@pytest.mark.parametrize('storage',['SSD','INTELLIGENT_TIERING'])
@pytest.mark.parametrize('size',[4,8,16,32,64,128,256,512,1024,2048,4096,3,129,8192])
def test_record_size(storage,size):
    d,r,*_=fixture(size,storage)
    allowed=(128,256,512,1024,2048,4096) if storage=='INTELLIGENT_TIERING' else (4,8,16,32,64,128,256,512,1024)
    assert evaluate_fsx_volume_parent(d,r)[0]['verdict']==('PASS' if size in allowed else 'FAIL')


@pytest.mark.parametrize('reservation,quota,expected',[(101,100,'FAIL'),(100,100,'NEEDS_REVIEW'),(99,100,'NEEDS_REVIEW'),(1001,-1,'FAIL'),(1000,-1,'NEEDS_REVIEW'),(0,100,'NOT_APPLICABLE'),(-1,100,'NOT_APPLICABLE'),(UNKNOWN,100,'NEEDS_REVIEW'),(True,100,'NEEDS_REVIEW'),(1,0,'FAIL')])
def test_reservation_upper_bound(reservation,quota,expected):
    d,r,*_=fixture(reservation=reservation,quota=quota)
    assert evaluate_fsx_volume_parent(d,r)[1]['verdict']==expected


@pytest.mark.parametrize('mode',['cycle','conditional','external','scope','template','storage_unknown','size_unknown','tiered_capacity'])
def test_unknown_chain(mode):
    d,r,p,fs=fixture(reservation=1001,quota=-1)
    if mode=='cycle':d.relations[-1].target_resource_id=r.id
    if mode=='conditional':d.relations[-1].condition='maybe'
    if mode=='external':d.relations.pop()
    if mode=='scope':fs.scope.region='us-east-1'
    if mode=='template':fs.template=TemplateContext(state='UNRESOLVED')
    if mode in ('storage_unknown','tiered_capacity'):next(f for f in fs.fields if f.path=='/properties/StorageType').candidates[0].value=UNKNOWN if mode=='storage_unknown' else 'INTELLIGENT_TIERING'
    if mode=='size_unknown':next(f for f in r.fields if f.path=='/properties/OpenZFSConfiguration').candidates[0].value['RecordSizeKiB']=UNKNOWN
    found=evaluate_fsx_volume_parent(d,r)
    assert found[0]['verdict']==('PASS' if mode=='tiered_capacity' else 'NEEDS_REVIEW')
    assert found[1]['verdict']==('FAIL' if mode=='size_unknown' else 'NEEDS_REVIEW')


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1];d,r,*_=fixture(size=4,storage='INTELLIGENT_TIERING')
    assert any(f['rule_id']=='FSX_OPENZFS_RECORD_SIZE_CLASS' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'])
