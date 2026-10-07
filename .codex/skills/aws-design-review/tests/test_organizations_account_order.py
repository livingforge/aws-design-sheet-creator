import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.organizations.account_order import evaluate_organizations_account_order
from test_autoscaling_group_and_scaling_policy import target,linked_design
from test_template_dependencies import template,link


def fixture(dependencies):
    nodes=[template(target(name,'AWS::Organizations::Account'),deps) for name,deps in dependencies.items()]
    return linked_design(nodes[0],nodes[1:]),nodes[0]


@pytest.mark.parametrize('dependencies,expected',[
    ({'a':[]},'NOT_APPLICABLE'),
    ({'a':[],'b':['a']},'PASS'),
    ({'a':['b'],'b':[]},'PASS'),
    ({'a':[],'b':['a'],'c':['b']},'PASS'),
    ({'a':[],'b':['a'],'c':['a']},'FAIL'),
    ({'a':[],'b':[]},'FAIL'),
    ({'a':['b'],'b':['a']},'FAIL'),
    ({'a':[],'b':None},'NEEDS_REVIEW'),
    ({'a':[],'b':['unknown']},'NEEDS_REVIEW'),
    ({'a':[],'b':['a','unknown']},'PASS')])
def test_total_order_not_just_shared_predecessor(dependencies,expected):
    d,r=fixture(dependencies)
    assert evaluate_organizations_account_order(d,r)[0]['verdict']==expected


def test_intermediate_resource_can_serialize_accounts():
    d,r=fixture({'a':[],'b':['bridge']})
    d.resources.append(template(target('bridge','AWS::SSM::Parameter'),['a']))
    assert evaluate_organizations_account_order(d,r)[0]['verdict']=='PASS'


def test_implicit_only_order_is_held_for_explicit_dependson_requirement():
    d,r=fixture({'a':[],'b':[]})
    link(d,d.resources[1],'Tags/0/Value',r)
    assert evaluate_organizations_account_order(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('mode,expected',[
    ('no_template','NEEDS_REVIEW'),('unknown_template','NEEDS_REVIEW'),
    ('different_template','NOT_APPLICABLE'),('different_scope','NOT_APPLICABLE'),
    ('duplicate_name','NEEDS_REVIEW')])
def test_template_boundaries(mode,expected):
    d,r=fixture({'a':[],'b':['a']})
    if mode=='no_template':r.template=None
    if mode=='unknown_template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='different_template':d.resources[1].template.id='another'
    if mode=='different_scope':d.resources[1].scope.region='us-east-1'
    if mode=='duplicate_name':d.resources.append(template(target('a-copy','AWS::SSM::Parameter')));d.resources[-1].name='a'
    assert evaluate_organizations_account_order(d,r)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r=fixture({'a':[],'b':['a']});root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='ORGANIZATIONS_ACCOUNT_SEQUENTIAL_CREATION' and f['verdict']=='PASS' for f in results)
