import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.pcs.vpc import evaluate_pcs_vpc
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture():
    r=target('nodes','AWS::PCS::ComputeNodeGroup',SubnetIds=['a','b'])
    c=target('cluster','AWS::PCS::Cluster',Networking={'SubnetIds':['control']})
    ss=[target(n,'AWS::EC2::Subnet',VpcId='vpc-12345678') for n in ('a','b','control')]
    d=linked_design(r,[c]+ss);link(d,r,'ClusterId',c)
    for i,s in enumerate(ss[:2]):link(d,r,'SubnetIds/'+str(i),s)
    link(d,c,'Networking/SubnetIds/0',ss[2])
    return d,r,c,ss


def verdict(d,r):return evaluate_pcs_vpc(d,r)[0]['verdict']


@pytest.mark.parametrize('index',[0,1,2])
def test_each_subnet_mismatch(index):
    d,r,c,ss=fixture();ss[index].fields[0].candidates[0].value='vpc-87654321'
    assert verdict(d,r)=='FAIL'


def test_same_vpc():
    d,r,*_=fixture();assert verdict(d,r)=='PASS'


@pytest.mark.parametrize('mode',['missing','conditional','duplicate','region','account','template','unknown_vpc','missing_vpc','unknown_list','empty_list','literal_cluster','unknown_cluster','cluster_scope'])
def test_uncertainty(mode):
    d,r,c,ss=fixture()
    if mode=='missing':d.resources.remove(ss[1])
    if mode=='conditional':d.relations[2].condition='Maybe'
    if mode=='duplicate':link(d,r,'SubnetIds/1',ss[1])
    if mode=='region':ss[1].scope.region='us-east-1'
    if mode=='account':ss[1].scope.account='222222222222'
    if mode=='template':ss[1].template=TemplateContext(state='UNRESOLVED')
    if mode=='unknown_vpc':ss[1].fields[0].candidates[0].value=UNKNOWN
    if mode=='missing_vpc':ss[1].fields=[]
    if mode=='unknown_list':r.fields[0].candidates[0].value=UNKNOWN
    if mode=='empty_list':r.fields[0].candidates[0].value=[]
    if mode in ('literal_cluster','unknown_cluster'):r.fields+=target('dummy',r.type,ClusterId='pcs_123' if mode=='literal_cluster' else UNKNOWN).fields
    if mode=='cluster_scope':c.scope.region='us-east-1'
    assert verdict(d,r)=='NEEDS_REVIEW'


@pytest.mark.parametrize('mode,expected',[('same','PASS'),('different','FAIL'),('mixed','NEEDS_REVIEW'),('literal_conflict','NEEDS_REVIEW')])
def test_logical_vpc_identity(mode,expected):
    d,r,c,ss=fixture();a=target('vpcA','AWS::EC2::VPC');b=target('vpcB','AWS::EC2::VPC');d.resources.extend([a,b])
    for i,s in enumerate(ss):
        if mode=='mixed' and i==1:continue
        if mode!='literal_conflict' or i!=1:s.fields=[]
        link(d,s,'VpcId',b if mode=='different' and i==1 else a)
    assert verdict(d,r)==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='PCS_COMPUTE_CLUSTER_VPC' and f['verdict']=='PASS' for f in results)
