import pytest
from aws_design_sheet.checks.dms.vpc_alignment import evaluate_dms_vpc_alignment, CONFIGS
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import link
from test_config_pipeline import nested


@pytest.mark.parametrize('kind',CONFIGS)
@pytest.mark.parametrize('identity',['literal','linked','mixed'])
@pytest.mark.parametrize('case',['same','different','conditional','external','scope','unknown','no_subnet_group','empty_groups','unknown_subnets','different_subnets'])
def test_membership(kind,identity,case):
    subnet_path,sg_path,_,_=CONFIGS[kind]
    props=nested(sg_path.split('/'),[] if case=='empty_groups' else ['security'])
    parent=props
    for key in subnet_path.split('/')[:-1]:parent=parent.setdefault(key,{})
    parent[subnet_path.split('/')[-1]]='group'
    r=target('main',kind,**props)
    group=target('group','AWS::DMS::ReplicationSubnetGroup',SubnetIds=UNKNOWN if case=='unknown_subnets' else ['subnet','other'])
    s=target('subnet','AWS::EC2::Subnet',VpcId='vpc-12345678')
    other=target('other','AWS::EC2::Subnet',VpcId='vpc-87654321' if case=='different_subnets' else 'vpc-12345678')
    sg=target('security','AWS::EC2::SecurityGroup',VpcId=UNKNOWN if case=='unknown' else 'vpc-87654321' if case=='different' else 'vpc-12345678')
    v1=target('v1','AWS::EC2::VPC');v2=target('v2','AWS::EC2::VPC')
    d=linked_design(r,[group,s,other,sg,v1,v2])
    if case!='no_subnet_group':link(d,r,subnet_path,group)
    if case!='unknown_subnets':
        link(d,group,'SubnetIds/0',s);link(d,group,'SubnetIds/1',other)
    if case not in ('external','empty_groups'):link(d,r,sg_path+'/0',sg)
    if case=='conditional':d.relations[-1].condition='maybe'
    if case=='scope':sg.scope.account='222222222222'
    if identity in ('linked','mixed'):
        link(d,s,'VpcId',v1);link(d,other,'VpcId',v2 if case=='different_subnets' else v1)
    if identity=='linked' and case!='unknown':link(d,sg,'VpcId',v2 if case=='different' else v1)
    expected='NEEDS_REVIEW'
    if case=='same' and identity!='mixed':expected='PASS'
    if case=='different' and identity!='mixed' or case=='different_subnets':expected='FAIL'
    assert evaluate_dms_vpc_alignment(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('kind',CONFIGS)
def test_absent_groups(kind):
    r=target('main',kind);d=linked_design(r)
    assert evaluate_dms_vpc_alignment(d,r)==[]
