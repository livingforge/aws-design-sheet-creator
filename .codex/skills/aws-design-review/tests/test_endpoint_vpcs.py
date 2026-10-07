from pathlib import Path
import pytest
from aws_design_sheet.checks.transfer.webapp_subnet_vpc import evaluate_transfer_webapp_subnet_vpc
from aws_design_sheet.checks.pipes.ecs_vpc_list_identity import evaluate_pipes_ecs_vpc_list_identity
from aws_design_sheet.checks.registry import combine
endpoint_vpcs_checks = combine(evaluate_transfer_webapp_subnet_vpc, evaluate_pipes_ecs_vpc_list_identity)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('case',['same','different','unknown','default','external','conditional','duplicate','invalid','wrong_type','unknown_vpc'])
def test_webapp(case):
 config={'VpcId':UNKNOWN if case=='unknown_vpc' else 'vpc-12345678','SubnetIds':['subnet']}
 r=target('main','AWS::Transfer::WebApp',EndpointDetails={'Vpc':config})
 owner='vpc-87654321' if case=='different' else UNKNOWN if case=='unknown' else 'invalid' if case=='invalid' else 'vpc-12345678'
 s=target('subnet','AWS::S3::Bucket' if case=='wrong_type' else 'AWS::EC2::Subnet',**({} if case=='default' else {'VpcId':owner}))
 links=[] if case=='external' else [('EndpointDetails/Vpc/SubnetIds/0','subnet')]*(2 if case=='duplicate' else 1)
 d=linked_design(r,[s],links)
 if case=='conditional':d.relations[0].condition='condition'
 assert endpoint_vpcs_checks(d,r)[0]['verdict']==('PASS' if case=='same' else 'FAIL' if case=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('key,kind',[('Subnets','AWS::EC2::Subnet'),('SecurityGroups','AWS::EC2::SecurityGroup')])
@pytest.mark.parametrize('case',['same','different','unknown','external','empty','unknown_list','conditional'])
def test_pipe(key,kind,case):
 raw=[] if case=='empty' else UNKNOWN if case=='unknown_list' else ['a','b']
 r=target('main','AWS::Pipes::Pipe',TargetParameters={'EcsTaskParameters':{'NetworkConfiguration':{'AwsvpcConfiguration':{key:raw}}}})
 a=target('a',kind,VpcId='vpc-12345678');b=target('b',kind,VpcId=UNKNOWN if case=='unknown' else 'vpc-87654321' if case=='different' else 'vpc-12345678')
 root='TargetParameters/EcsTaskParameters/NetworkConfiguration/AwsvpcConfiguration/'+key
 links=[(root+'/0','a')]+([] if case=='external' else [(root+'/1','b')])
 d=linked_design(r,[a,b],links)
 if case=='conditional':d.relations[1].condition='condition'
 assert endpoint_vpcs_checks(d,r)[0]['verdict']==('PASS' if case=='same' else 'FAIL' if case=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::Transfer::WebApp','AWS::Pipes::Pipe'])
def test_absent(kind):
 r=target('main',kind);assert not endpoint_vpcs_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::Transfer::WebApp',EndpointDetails={'Vpc':{'VpcId':'vpc-12345678','SubnetIds':['subnet']}})
 s=target('subnet','AWS::EC2::Subnet',VpcId='vpc-87654321')
 d=linked_design(r,[s],[('EndpointDetails/Vpc/SubnetIds/0','subnet')]);root=Path(__file__).resolve().parents[1]
 found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
 assert any(f['rule_id']=='TRANSFER_WEBAPP_SUBNET_VPC' and f['verdict']=='FAIL' for f in found)
