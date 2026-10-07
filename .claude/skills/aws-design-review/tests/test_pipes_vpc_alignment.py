import pytest
from aws_design_sheet.checks.pipes.vpc_alignment import evaluate_pipes_vpc_alignment, ROOTS
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import link
from test_config_pipeline import nested


@pytest.mark.parametrize('root,groups',ROOTS)
@pytest.mark.parametrize('identity',['literal','linked','mixed'])
@pytest.mark.parametrize('case',['same','different','conditional','external','scope','unknown','default_groups','empty_groups'])
def test_cross_list(root,groups,identity,case):
    props={'Subnets':['subnet']}
    if case!='default_groups':props[groups]=[] if case=='empty_groups' else ['group']
    r=target('main','AWS::Pipes::Pipe',**nested(root.split('/')[2:],props))
    s=target('subnet','AWS::EC2::Subnet',VpcId='vpc-12345678')
    sg=target('group','AWS::EC2::SecurityGroup',VpcId=UNKNOWN if case=='unknown' else 'vpc-87654321' if case=='different' else 'vpc-12345678')
    v1=target('v1','AWS::EC2::VPC');v2=target('v2','AWS::EC2::VPC')
    d=linked_design(r,[s,sg,v1,v2]);link(d,r,root.removeprefix('/properties/')+'/Subnets/0',s)
    if case not in ('external','default_groups','empty_groups'):link(d,r,root.removeprefix('/properties/')+'/'+groups+'/0',sg)
    if case=='conditional':d.relations[-1].condition='maybe'
    if case=='scope':sg.scope.account='222222222222'
    if identity in ('linked','mixed'):link(d,s,'VpcId',v1)
    if identity=='linked' and case!='unknown':link(d,sg,'VpcId',v2 if case=='different' else v1)
    expected='PASS' if case in ('default_groups','empty_groups') else 'NEEDS_REVIEW'
    if case in ('same','different') and identity!='mixed':expected='PASS' if case=='same' else 'FAIL'
    assert evaluate_pipes_vpc_alignment(d,r)[0]['verdict']==expected


def test_source_target_vpcs_are_independent():
    r=target('main','AWS::Pipes::Pipe',TargetParameters={'EcsTaskParameters':{'NetworkConfiguration':{'AwsvpcConfiguration':{'Subnets':['a']}}}},SourceParameters={'SelfManagedKafkaParameters':{'Vpc':{'Subnets':['b']}}})
    a=target('a','AWS::EC2::Subnet',VpcId='vpc-12345678');b=target('b','AWS::EC2::Subnet',VpcId='vpc-87654321')
    d=linked_design(r,[a,b])
    for (root,_),subnet in zip(ROOTS,(a,b)):link(d,r,root.removeprefix('/properties/')+'/Subnets/0',subnet)
    assert [f['verdict'] for f in evaluate_pipes_vpc_alignment(d,r)]==['PASS','PASS']
