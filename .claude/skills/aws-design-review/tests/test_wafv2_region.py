from pathlib import Path
import pytest
from aws_design_sheet.checks.wafv2.region import evaluate_wafv2_region
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('kind',['IPSet','RegexPatternSet','RuleGroup','WebACL'])
@pytest.mark.parametrize('scope,region,expected',[
 ('CLOUDFRONT','us-east-1','PASS'),('CLOUDFRONT','ap-northeast-1','FAIL'),
 ('REGIONAL','ap-northeast-1','NOT_APPLICABLE'),(UNKNOWN,'ap-northeast-1','NEEDS_REVIEW'),
 ('cloudfront','ap-northeast-1','NEEDS_REVIEW'),('CLOUDFRONT','unknown','NEEDS_REVIEW')])
def test_region(kind,scope,region,expected):
 r=target('main','AWS::WAFv2::'+kind,Scope=scope);r.scope.region=region
 assert evaluate_wafv2_region(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('kind',['IPSet','RegexPatternSet','RuleGroup','WebACL'])
def test_absent(kind):
 r=target('main','AWS::WAFv2::'+kind);assert not evaluate_wafv2_region(linked_design(r),r)


def test_checker_supported_region():
 r=target('main','AWS::WAFv2::IPSet',Scope='CLOUDFRONT');root=Path(__file__).resolve().parents[1]
 found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='WAFV2_IPSET_CLOUDFRONT_REGION' and f['verdict']=='FAIL' for f in found)
