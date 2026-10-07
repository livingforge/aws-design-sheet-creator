import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.datasync.efs_placement import evaluate_datasync_efs_placement
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(own=None,other=None):
    r=target('main','AWS::DataSync::LocationEFS',Ec2Config={'SubnetArn':'subnet'},EfsFilesystemArn='fs')
    a=target('subnet','AWS::EC2::Subnet',**(own if own is not None else {'VpcId':'vpc-12345678','AvailabilityZone':'ap-northeast-1a'}))
    b=target('mount-subnet','AWS::EC2::Subnet',**(other if other is not None else {'VpcId':'vpc-12345678','AvailabilityZone':'ap-northeast-1a'}))
    fs=target('fs','AWS::EFS::FileSystem');m=target('mount','AWS::EFS::MountTarget',FileSystemId='fs',SubnetId='mount-subnet')
    d=linked_design(r,[a,b,fs,m],[('Ec2Config/SubnetArn','subnet'),('EfsFilesystemArn','fs')])
    link(d,m,'FileSystemId',fs);link(d,m,'SubnetId',b)
    return d,r,a,b,fs,m


@pytest.mark.parametrize('a,b,expected',[
    ({'VpcId':'vpc-12345678','AvailabilityZone':'ap-northeast-1a'},{'VpcId':'vpc-12345678','AvailabilityZone':'ap-northeast-1a'},'PASS'),
    ({'VpcId':'vpc-12345678','AvailabilityZoneId':'apne1-az1'},{'VpcId':'vpc-12345678','AvailabilityZoneId':'apne1-az1'},'PASS'),
    ({'VpcId':'vpc-12345678'},{'VpcId':'vpc-23456789'},'FAIL'),
    ({'VpcId':'vpc-12345678','AvailabilityZone':'ap-northeast-1a'},{'VpcId':'vpc-12345678','AvailabilityZone':'ap-northeast-1b'},'NEEDS_REVIEW'),
    ({'VpcId':'vpc-12345678','AvailabilityZone':'ap-northeast-1a'},{'VpcId':'vpc-12345678','AvailabilityZoneId':'apne1-az1'},'NEEDS_REVIEW'),
    ({'VpcId':UNKNOWN},{'VpcId':'vpc-23456789'},'NEEDS_REVIEW'),
    ({'VpcId':'vpc-12345678','AvailabilityZone':UNKNOWN},{'VpcId':'vpc-12345678','AvailabilityZone':UNKNOWN},'NEEDS_REVIEW'),
    ({},{},'NEEDS_REVIEW'),
    ({'VpcId':'vpc-12345678','AvailabilityZone':'ap-northeast-1a','AvailabilityZoneId':'apne1-az1'},{'VpcId':'vpc-12345678','AvailabilityZone':'ap-northeast-1a','AvailabilityZoneId':'apne1-az2'},'NEEDS_REVIEW'),
])
def test_placement(a,b,expected):
    d,r,*_=fixture(a,b)
    assert evaluate_datasync_efs_placement(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['same_subnet','vpc_ref','different_vpc_ref','mixed_identity','conditional','external','no_mount','scope','template','arn','unknown_parent'])
def test_explicit_evidence(mode):
    d,r,a,b,fs,m=fixture()
    expected='NEEDS_REVIEW'
    if mode=='same_subnet':
        d.relations[-1].target_resource_id=a.id;a.fields=[];expected='PASS'
    if mode in ('vpc_ref','different_vpc_ref','mixed_identity'):
        v=target('vpc','AWS::EC2::VPC');w=target('other-vpc','AWS::EC2::VPC');d.resources.extend([v,w]);link(d,a,'VpcId',v)
        if mode!='mixed_identity':link(d,b,'VpcId',w if mode=='different_vpc_ref' else v)
        expected='FAIL' if mode=='different_vpc_ref' else 'PASS' if mode=='vpc_ref' else 'NEEDS_REVIEW'
    if mode=='conditional':d.relations[-1].condition='maybe'
    if mode=='external':d.relations.pop(1)
    if mode=='no_mount':d.resources.remove(m)
    if mode=='scope':b.scope.region='us-east-1'
    if mode=='template':fs.template=TemplateContext(state='UNRESOLVED')
    if mode=='arn':next(f for f in r.fields if f.path=='/properties/Ec2Config').candidates[0].value={'SubnetArn':'arn:aws:ec2:us-east-1:123456789012:subnet/subnet-12345678'}
    if mode=='unknown_parent':next(f for f in r.fields if f.path=='/properties/Ec2Config').candidates[0].value=UNKNOWN
    assert evaluate_datasync_efs_placement(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('mode,expected',[('additional_unknown','PASS'),('additional_mismatch','FAIL'),('additional_other_az','PASS')])
def test_existential_match_and_known_conflict(mode,expected):
    d,r,a,b,fs,m=fixture()
    c=target('extra-subnet','AWS::EC2::Subnet',VpcId='vpc-23456789' if mode=='additional_mismatch' else 'vpc-12345678',AvailabilityZone='ap-northeast-1b')
    n=target('extra-mount','AWS::EFS::MountTarget',FileSystemId='fs',SubnetId='extra-subnet')
    d.resources.extend([c,n]);link(d,n,'FileSystemId',fs);link(d,n,'SubnetId',c)
    if mode=='additional_unknown':d.relations[-1].condition='maybe'
    assert evaluate_datasync_efs_placement(d,r)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    d,r,*_=fixture({'VpcId':'vpc-12345678'},{'VpcId':'vpc-23456789'})
    assert any(f['rule_id']=='DATASYNC_EFS_SUBNET_PLACEMENT' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'])
