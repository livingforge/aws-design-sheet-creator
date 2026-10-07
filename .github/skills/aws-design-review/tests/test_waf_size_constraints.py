from pathlib import Path
import pytest
from aws_design_sheet.checks.waf.size_constraints import evaluate_waf_size_constraints, evaluate_wafregional_size_constraints
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
classic_sizes_checks = combine(evaluate_waf_size_constraints, evaluate_wafregional_size_constraints)


@pytest.mark.parametrize('raw,expected',[('IPV4','PASS'),('IPV6','PASS'),('IPv6','FAIL'),('OTHER','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_ip(raw,expected):
 r=target('main','AWS::WAFRegional::IPSet',IPSetDescriptors=[{'Type':raw}])
 assert classic_sizes_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('namespace',['WAF','WAFRegional'])
@pytest.mark.parametrize('key,raw,expected',[
 ('ComparisonOperator','EQ','PASS'),('ComparisonOperator','NE','PASS'),('ComparisonOperator','LE','PASS'),('ComparisonOperator','LT','PASS'),('ComparisonOperator','GE','PASS'),('ComparisonOperator','GT','PASS'),('ComparisonOperator','eq','FAIL'),('ComparisonOperator','BETWEEN','FAIL'),('ComparisonOperator',UNKNOWN,'NEEDS_REVIEW'),
 ('TextTransformation','NONE','PASS'),('TextTransformation','COMPRESS_WHITE_SPACE','PASS'),('TextTransformation','HTML_ENTITY_DECODE','PASS'),('TextTransformation','LOWERCASE','PASS'),('TextTransformation','CMD_LINE','PASS'),('TextTransformation','URL_DECODE','PASS'),('TextTransformation','BASE64_DECODE','FAIL'),('TextTransformation','lowercase','FAIL'),('TextTransformation',UNKNOWN,'NEEDS_REVIEW')])
def test_size_values(namespace,key,raw,expected):
 r=target('main','AWS::'+namespace+'::SizeConstraintSet',SizeConstraints=[{key:raw}])
 found=classic_sizes_checks(linked_design(r),r)
 assert len(found)==1 and found[0]['verdict']==expected


@pytest.mark.parametrize('namespace',['WAF','WAFRegional'])
def test_unknown_collection(namespace):
 r=target('main','AWS::'+namespace+'::SizeConstraintSet',SizeConstraints=UNKNOWN)
 found=classic_sizes_checks(linked_design(r),r)
 assert len(found)==1 and found[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('kind',['AWS::WAFRegional::IPSet','AWS::WAF::SizeConstraintSet','AWS::WAFRegional::SizeConstraintSet'])
def test_absent(kind):
 r=target('main',kind);assert not classic_sizes_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::WAFRegional::SizeConstraintSet',SizeConstraints=[{'ComparisonOperator':'BETWEEN'}]);root=Path(__file__).resolve().parents[1]
 found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='WAFREGIONAL_SIZE_CONDITION_VALUES' and f['verdict']=='FAIL' for f in found)
