import pytest
from aws_design_sheet.checks.waf.predicates import evaluate_waf_predicates
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link

KINDS=[('IPMatch','IPSet'),('ByteMatch','ByteMatchSet'),('SqlInjectionMatch','SqlInjectionMatchSet'),('SizeConstraint','SizeConstraintSet'),('XssMatch','XssMatchSet')]


def fixture(type='AWS::WAF::Rule',kind='IPMatch',suffix='IPSet'):
    prop='MatchPredicates' if type.endswith('RateBasedRule') else 'Predicates'
    r=target('rule',type,**{prop:[{'Type':kind,'Negated':False}]})
    other=target('set','::'.join(type.split('::')[:2])+'::'+suffix)
    d=linked_design(r,[other]);link(d,r,prop+'/0/DataId',other)
    return d,r,other


def verdict(d,r):return evaluate_waf_predicates(d,r)[0]['verdict']


@pytest.mark.parametrize('type',['AWS::WAF::Rule','AWS::WAFRegional::Rule','AWS::WAFRegional::RateBasedRule'])
@pytest.mark.parametrize('kind,suffix',KINDS)
def test_predicate_mapping(type,kind,suffix):
    d,r,*_=fixture(type,kind,suffix);assert verdict(d,r)=='PASS'


@pytest.mark.parametrize('kind,suffix,want',[('IPMatch','ByteMatchSet','FAIL'),('Bogus','IPSet','FAIL'),(UNKNOWN,'IPSet','NEEDS_REVIEW'),('RegexMatch','RegexPatternSet','NEEDS_REVIEW'),('GeoMatch','GeoMatchSet','PASS')])
def test_target_kind(kind,suffix,want):
    d,r,*_=fixture('AWS::WAFRegional::Rule',kind,suffix);assert verdict(d,r)==want


@pytest.mark.parametrize('mode',['literal','conditional','missing','duplicate','region','unknown_parent'])
def test_reference_uncertainty(mode):
    d,r,o=fixture()
    if mode=='literal':r.fields[0].candidates[0].value[0]['DataId']='physical-id'
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='missing':d.resources.remove(o)
    if mode=='duplicate':link(d,r,'Predicates/0/DataId',o)
    if mode=='region':o.scope.region='us-east-1'
    if mode=='unknown_parent':r.fields[0].candidates[0].value=UNKNOWN
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_regional_set_is_not_global_set():
    d,r,o=fixture();o.type='AWS::WAFRegional::IPSet'
    assert verdict(d,r)=='FAIL'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='WAF_CLASSIC_PREDICATE_TARGET' and f['verdict']=='PASS' for f in results)
