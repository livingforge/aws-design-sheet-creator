import pytest
from aws_design_sheet.checks.refactorspaces.default import evaluate_refactorspaces_default
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(state='ACTIVE'):
    common={'ApplicationIdentifier':'app-1234567890','EnvironmentIdentifier':'env-1234567890'}
    r=target('route','AWS::RefactorSpaces::Route',**common,RouteType='URI_PATH',UriPathRoute={'ActivationState':'ACTIVE'})
    default=target('default','AWS::RefactorSpaces::Route',**common,RouteType='DEFAULT',DefaultRoute={'ActivationState':state})
    return linked_design(r,[default]),r,default


def verdict(d,r):return evaluate_refactorspaces_default(d,r)[0]['verdict']


@pytest.mark.parametrize('state,want',[('ACTIVE','PASS'),('INACTIVE','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_required_default_state(state,want):
    d,r,*_=fixture(state);assert verdict(d,r)==want


@pytest.mark.parametrize('mode',['no_default','other_app','other_environment','other_account','unknown_app','multiple_defaults','omitted_state'])
def test_incomplete_inventory(mode):
    d,r,default=fixture()
    if mode=='no_default':d.resources.remove(default)
    if mode=='other_app':default.fields[0].candidates[0].value='app-abcdefghij'
    if mode=='other_environment':default.fields[1].candidates[0].value='env-abcdefghij'
    if mode=='other_account':default.scope.account='222222222222'
    if mode=='unknown_app':r.fields[0].candidates[0].value=UNKNOWN
    if mode=='multiple_defaults':copy=default.model_copy(deep=True);copy.id='second';d.resources.append(copy)
    if mode=='omitted_state':default.fields[-1].candidates[0].value={}
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_inactive_uri_route():
    d,r,*_=fixture('INACTIVE');r.fields[-1].candidates[0].value={'ActivationState':'INACTIVE'}
    assert verdict(d,r)=='NOT_APPLICABLE'


def test_logical_application_and_environment():
    d,r,default=fixture();a=target('app','AWS::RefactorSpaces::Application');e=target('env','AWS::RefactorSpaces::Environment');d.resources.extend([a,e])
    for x in (r,default):
        x.fields=x.fields[2:];link(d,x,'ApplicationIdentifier',a);link(d,x,'EnvironmentIdentifier',e)
    assert verdict(d,r)=='PASS'
    d.relations[0].condition='Maybe'
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="REFACTOR_SPACES_ACTIVE_DEFAULT" and f["verdict"]=="PASS" for f in results)
