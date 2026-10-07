import pytest
from aws_design_sheet.checks.waf.scalar_values import evaluate_waf_scalar_values, evaluate_wafregional_scalar_values
from aws_design_sheet.checks.registry import combine
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
waf_scalar_values_checks=combine(evaluate_waf_scalar_values,evaluate_wafregional_scalar_values)


@pytest.mark.parametrize('scope',['WAF','WAFRegional'])
@pytest.mark.parametrize('raw,want',[('a','PASS'),('a'*128,'PASS'),('a'*129,'FAIL'),('','FAIL'),(' \t','FAIL'),(' a ','PASS'),('a\nb','NEEDS_REVIEW'),('a\rb','NEEDS_REVIEW'),('${Name}','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),('日本語','NEEDS_REVIEW')])
def test_name_and_data(scope,raw,want):
    r=target('set','AWS::'+scope+'::ByteMatchSet',Name=raw,ByteMatchTuples=[{'FieldToMatch':{'Type':'HEADER','Data':raw}}])
    results=waf_scalar_values_checks(linked_design(r),r)
    assert len(results)==2
    assert all(f['verdict']==want for f in results)


@pytest.mark.parametrize('kind,transform,want',[('URI','NONE','PASS'),('SINGLE_QUERY_ARG','CMD_LINE','PASS'),('BAD','BAD','FAIL'),(UNKNOWN,UNKNOWN,'NEEDS_REVIEW')])
def test_sql_enums(kind,transform,want):
    r=target('set','AWS::WAF::SqlInjectionMatchSet',SqlInjectionMatchTuples=[{'FieldToMatch':{'Type':kind},'TextTransformation':transform}])
    results=waf_scalar_values_checks(linked_design(r),r)
    assert len(results)==2
    assert all(f['verdict']==want for f in results)


def test_unknown_ancestor_and_optional_absence():
    r=target('set','AWS::WAF::ByteMatchSet',Name='name',ByteMatchTuples=UNKNOWN)
    results=waf_scalar_values_checks(linked_design(r),r)
    assert [f['verdict'] for f in results]==['PASS','NEEDS_REVIEW']
    r.fields[1].candidates[0].value=[{'FieldToMatch':{'Type':'METHOD'}}]
    assert len(waf_scalar_values_checks(linked_design(r),r))==1


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    r=target('set','AWS::WAF::ByteMatchSet',Name='valid')
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='WAF_CLASSIC_BYTE_NAME_DATA' and f['verdict']=='PASS' for f in results)
