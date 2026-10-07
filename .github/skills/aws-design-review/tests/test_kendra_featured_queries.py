import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.kendra.featured_queries import evaluate_kendra_featured_queries
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link

INDEX='12345678-1234-1234-1234-123456789012'


def fixture(first=None,second=None,logical=False):
    r=target('first','AWS::Kendra::FeaturedResultsSet',QueryTexts=first if first is not None else ['How Kendra works'])
    other=target('second','AWS::Kendra::FeaturedResultsSet',QueryTexts=second if second is not None else ['how kendra works'],Status='INACTIVE')
    index=target('index','AWS::Kendra::Index')
    d=linked_design(r,[other,index])
    if logical:
        link(d,r,'IndexId',index);link(d,other,'IndexId',index)
    else:
        for item in (r,other):
            item.fields+=target('dummy','AWS::Kendra::FeaturedResultsSet',IndexId=INDEX).fields
    return d,r,other,index


@pytest.mark.parametrize('logical',[False,True])
@pytest.mark.parametrize('status',['ACTIVE','INACTIVE',None])
def test_collisions_include_inactive_sets(logical,status):
    d,r,other,index=fixture(logical=logical)
    if status is None:other.fields=[f for f in other.fields if not f.path.endswith('/Status')]
    else:next(f for f in other.fields if f.path.endswith('/Status')).candidates[0].value=status
    assert evaluate_kendra_featured_queries(d,r)[0]['verdict']=='FAIL'


@pytest.mark.parametrize('first,second,expected',[
    (['HELLO  '],['hello\t'],'FAIL'),
    (['hello'],['hello '],'NEEDS_REVIEW'),
    (['a  b'],['a b'],'NEEDS_REVIEW'),
    (['a b'],['b'],'NEEDS_REVIEW'),
    ([' hello'],['hello'],'NEEDS_REVIEW'),
    (['hello',UNKNOWN],['HELLO'],'FAIL'),
    ([UNKNOWN],['hello'],'NEEDS_REVIEW'),
    (['\u0130'],['i'],'NEEDS_REVIEW'),
    (['hello','hello'],['world'],'NEEDS_REVIEW'),
    ([],['hello'],'NOT_APPLICABLE')])
def test_query_normalization_and_partial_evidence(first,second,expected):
    d,r,*_=fixture(first,second)
    assert evaluate_kendra_featured_queries(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',[
    'different_index','different_region','different_account','conditional_source',
    'conditional_peer','conditional_reference','unknown_index','literal_and_reference','missing_peer'])
def test_ambiguous_or_unrelated_sets_do_not_fail(mode):
    d,r,other,index=fixture(logical=mode in ('conditional_reference','literal_and_reference'))
    if mode=='different_index':other.fields[-1].candidates[0].value='87654321-1234-1234-1234-123456789012'
    if mode=='different_region':other.scope.region='us-east-1'
    if mode=='different_account':other.scope.account='222222222222'
    if mode=='conditional_source':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='conditional_peer':other.template=TemplateContext(state='UNRESOLVED')
    if mode=='conditional_reference':d.relations[-1].condition='Maybe'
    if mode=='unknown_index':r.fields[-1].candidates[0].value=UNKNOWN
    if mode=='literal_and_reference':r.fields+=target('dummy','AWS::Kendra::FeaturedResultsSet',IndexId=INDEX).fields
    if mode=='missing_peer':d.resources.remove(other)
    assert evaluate_kendra_featured_queries(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    findings=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='KENDRA_FEATURED_QUERY_COLLISION' and f['verdict']=='FAIL' for f in findings)
