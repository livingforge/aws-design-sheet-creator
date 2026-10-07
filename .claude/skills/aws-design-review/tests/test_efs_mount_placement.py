import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.efs.mount_placement import evaluate_efs_mount_placement
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('mode',['same','vpc','az','unknown_vpc','unknown_az','default','conditional','scope','template','external'])
def test_efs_placement(mode):
    r=target('main','AWS::EFS::MountTarget',FileSystemId='filesystem',SubnetId='subnet',SecurityGroups=['group'])
    fs=target('filesystem','AWS::EFS::FileSystem',**({} if mode=='default' else {'AvailabilityZoneName':'ap-northeast-1a'}))
    s=target('subnet','AWS::EC2::Subnet',VpcId='vpc-12345678',AvailabilityZone=UNKNOWN if mode=='unknown_az' else 'ap-northeast-1b' if mode=='az' else 'ap-northeast-1a')
    g=target('group','AWS::EC2::SecurityGroup',VpcId=UNKNOWN if mode=='unknown_vpc' else 'vpc-23456789' if mode=='vpc' else 'vpc-12345678')
    d=linked_design(r,[fs,s,g],[('FileSystemId','filesystem'),('SubnetId','subnet'),('SecurityGroups/0','group')])
    if mode=='conditional':d.relations[1].condition='maybe'
    if mode=='scope':s.scope.region='us-east-1'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='external':d.relations.pop(1)
    held=mode in ('conditional','scope','template','external')
    found={f['rule_id']:f['verdict'] for f in evaluate_efs_mount_placement(d,r)}
    assert found['EFS_MOUNT_SECURITY_GROUP_VPC']==('NEEDS_REVIEW' if held or mode=='unknown_vpc' else 'FAIL' if mode=='vpc' else 'PASS')
    assert found['EFS_MOUNT_ONE_ZONE_SUBNET']==('NEEDS_REVIEW' if held or mode in ('unknown_az','default') else 'FAIL' if mode=='az' else 'PASS')


@pytest.mark.parametrize('mode,expected',[('same','PASS'),('different','FAIL'),('mixed','NEEDS_REVIEW'),('conditional','NEEDS_REVIEW')])
def test_linked_vpc_identities(mode,expected):
    from test_template_dependencies import link
    r=target('main','AWS::EFS::MountTarget',SubnetId='subnet',SecurityGroups=['group'])
    s=target('subnet','AWS::EC2::Subnet',VpcId='vpc-12345678')
    g=target('group','AWS::EC2::SecurityGroup',VpcId='vpc-12345678')
    v=target('vpc','AWS::EC2::VPC');other=target('other','AWS::EC2::VPC')
    d=linked_design(r,[s,g,v,other],[('SubnetId','subnet'),('SecurityGroups/0','group')]);link(d,s,'VpcId',v)
    if mode!='mixed':link(d,g,'VpcId',other if mode=='different' else v)
    if mode=='conditional':d.relations[-1].condition='maybe'
    assert evaluate_efs_mount_placement(d,r)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::EFS::MountTarget',SubnetId='subnet',SecurityGroups=['group'])
    s=target('subnet','AWS::EC2::Subnet',VpcId='vpc-12345678');g=target('group','AWS::EC2::SecurityGroup',VpcId='vpc-23456789')
    d=linked_design(r,[s,g],[('SubnetId','subnet'),('SecurityGroups/0','group')])
    assert any(f['rule_id']=='EFS_MOUNT_SECURITY_GROUP_VPC' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'])
