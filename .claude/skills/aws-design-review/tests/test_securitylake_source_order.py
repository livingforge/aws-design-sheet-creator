import pytest
from aws_design_sheet.checks.securitylake.source_order import evaluate_securitylake_source_order
from test_autoscaling_group_and_scaling_policy import target,linked_design
from test_template_dependencies import template,link


def fixture(dependencies):
    nodes=[template(target(name,'AWS::SecurityLake::AwsLogSource'),deps) for name,deps in dependencies.items()]
    return linked_design(nodes[0],nodes[1:]),nodes[0]


@pytest.mark.parametrize('dependencies,want',[
    ({'a':[]},'NOT_APPLICABLE'),({'a':[],'b':['a']},'PASS'),
    ({'a':[],'b':['a'],'c':['b']},'PASS'),({'a':[],'b':['a'],'c':['a']},'FAIL'),
    ({'a':[],'b':[]},'FAIL'),({'a':['b'],'b':['a']},'FAIL'),
    ({'a':[],'b':None},'NEEDS_REVIEW'),({'a':[],'b':['external']},'NEEDS_REVIEW')])
def test_source_order(dependencies,want):
    d,r=fixture(dependencies)
    assert evaluate_securitylake_source_order(d,r)[0]['verdict']==want


def test_implicit_order_is_not_explicit_dependson():
    d,r=fixture({'a':[],'b':[]});link(d,d.resources[1],'DataLakeArn',r)
    assert evaluate_securitylake_source_order(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_cross_region_not_claimed():
    d,r=fixture({'a':[],'b':[]});d.resources[1].scope.region='us-east-1'
    assert evaluate_securitylake_source_order(d,r)[0]['verdict']=='NOT_APPLICABLE'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r=fixture({'a':[],'b':['a']});root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='SECURITYLAKE_SOURCE_SEQUENTIAL' and f['verdict']=='PASS' for f in results)
