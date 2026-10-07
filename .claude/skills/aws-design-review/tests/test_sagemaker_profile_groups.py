import pytest
from aws_design_sheet.checks.sagemaker.profile_groups import evaluate_sagemaker_profile_groups
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(user,default,mode='VpcOnly'):
    r=target('profile','AWS::SageMaker::UserProfile',UserSettings=user)
    domain=target('domain','AWS::SageMaker::Domain',DefaultUserSettings=default,AppNetworkAccessType=mode)
    d=linked_design(r,[domain]);link(d,r,'DomainId',domain)
    return d,r,domain


@pytest.mark.parametrize('user,default,mode,want',[
    ({},{},'VpcOnly','FAIL'),({'SecurityGroups':[]},{},'VpcOnly','FAIL'),
    ({'SecurityGroups':['sg-12345678']},{},'VpcOnly','PASS'),
    ({},{'SecurityGroups':['sg-12345678']},'VpcOnly','PASS'),
    ({'SecurityGroups':[]},{'SecurityGroups':['sg-12345678']},'VpcOnly','PASS'),
    (UNKNOWN,{},'VpcOnly','NEEDS_REVIEW'),({},UNKNOWN,'VpcOnly','NEEDS_REVIEW'),
    (UNKNOWN,{'SecurityGroups':['sg-12345678']},'VpcOnly','PASS'),
    ({},{},'PublicInternetOnly','NOT_APPLICABLE'),({},{},UNKNOWN,'NEEDS_REVIEW')])
def test_inherited_presence(user,default,mode,want):
    d,r,_=fixture(user,default,mode)
    assert evaluate_sagemaker_profile_groups(d,r)[0]['verdict']==want


@pytest.mark.parametrize('case',['external','conditional','region','literal'])
def test_ambiguous_domain(case):
    d,r,domain=fixture({}, {})
    if case=='external':d.resources.remove(domain)
    if case=='conditional':d.relations[0].condition='Maybe'
    if case=='region':domain.scope.region='us-east-1'
    if case=='literal':r.fields.append(target('x','AWS::SageMaker::UserProfile',DomainId='d-12345678').fields[0])
    assert evaluate_sagemaker_profile_groups(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,_=fixture({}, {'SecurityGroups':['sg-12345678']});root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='SAGEMAKER_PROFILE_VPC_GROUPS' and f['verdict']=='PASS' for f in results)
