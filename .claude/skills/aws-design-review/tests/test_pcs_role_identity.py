import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.pcs.role_identity import evaluate_pcs_role_identity
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(name='AWSPCS-compute',path='/'):
    r=target('nodes','AWS::PCS::ComputeNodeGroup')
    profile=target('profile','AWS::IAM::InstanceProfile',Roles=[name])
    role=target('role','AWS::IAM::Role',RoleName=name,Path=path)
    d=linked_design(r,[profile,role]);link(d,r,'IamInstanceProfileArn',profile);link(d,profile,'Roles/0',role)
    return d,r,profile,role


def verdict(d,r):return evaluate_pcs_role_identity(d,r)[0]['verdict']


@pytest.mark.parametrize('name,path,want',[
    ('AWSPCS-compute','/','PASS'),('AWSPCS','/','PASS'),('compute','/aws-pcs/','PASS'),
    ('compute','/','FAIL'),('awspcs-role','/','FAIL'),('compute','/other/','FAIL'),
    ('compute','/other/aws-pcs/','NEEDS_REVIEW'),('compute','/aws-pcs/child/','NEEDS_REVIEW'),
    ('compute',UNKNOWN,'NEEDS_REVIEW'),('AWSPCS-compute',UNKNOWN,'PASS'),
    ('bad name','/','NEEDS_REVIEW')])
def test_naming_alternatives(name,path,want):
    d,r,*_=fixture(name,path);assert verdict(d,r)==want


@pytest.mark.parametrize('mode',['literal_profile','conditional','missing','duplicate','role_scope','role_template','unknown_roles','role_name_conflict','unknown_name'])
def test_uncertain_chain(mode):
    d,r,p,role=fixture()
    if mode=='literal_profile':r.fields+=target('dummy',r.type,IamInstanceProfileArn='arn:aws:iam::111111111111:instance-profile/profile').fields
    if mode=='conditional':d.relations[1].condition='Maybe'
    if mode=='missing':d.resources.remove(role)
    if mode=='duplicate':link(d,p,'Roles/0',role)
    if mode=='role_scope':role.scope.account='222222222222'
    if mode=='role_template':role.template=TemplateContext(state='UNRESOLVED')
    if mode=='unknown_roles':p.fields[0].candidates[0].value=UNKNOWN
    if mode=='role_name_conflict':p.fields[0].candidates[0].value=['other']
    if mode=='unknown_name':role.fields[0].candidates[0].value=UNKNOWN
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_default_role_path():
    d,r,p,role=fixture('compute');role.fields.pop()
    assert verdict(d,r)=='FAIL'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="PCS_INSTANCE_PROFILE_ROLE_IDENTITY" and f["verdict"]=="PASS" for f in results)
