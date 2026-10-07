from pathlib import Path
import pytest
from aws_design_sheet.checks.waf.xss_and_actions import evaluate_waf_xss_and_actions
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('raw,expected',[('ALLOW','PASS'),('BLOCK','PASS'),('COUNT','PASS'),('allow','FAIL'),('CAPTCHA','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_action(raw,expected):
 r=target('main','AWS::WAFRegional::WebACL',Rules=[{'Action':{'Type':raw}}])
 assert evaluate_waf_xss_and_actions(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('namespace',['WAF','WAFRegional'])
@pytest.mark.parametrize('raw,expected',[('NONE','PASS'),('COMPRESS_WHITE_SPACE','PASS'),('HTML_ENTITY_DECODE','PASS'),('LOWERCASE','PASS'),('CMD_LINE','PASS'),('URL_DECODE','PASS'),('BASE64_DECODE','FAIL'),('lowercase','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${transform}','NEEDS_REVIEW')])
def test_transform(namespace,raw,expected):
 r=target('main','AWS::'+namespace+'::XssMatchSet',XssMatchTuples=[{'TextTransformation':raw}])
 assert evaluate_waf_xss_and_actions(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('kind,key',[('AWS::WAFRegional::WebACL','Rules'),('AWS::WAF::XssMatchSet','XssMatchTuples'),('AWS::WAFRegional::XssMatchSet','XssMatchTuples')])
def test_unknown_collection(kind,key):
 r=target('main',kind,**{key:UNKNOWN});found=evaluate_waf_xss_and_actions(linked_design(r),r)
 assert len(found)==1 and found[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('kind',['AWS::WAFRegional::WebACL','AWS::WAF::XssMatchSet','AWS::WAFRegional::XssMatchSet'])
def test_absent(kind):
 r=target('main',kind);assert not evaluate_waf_xss_and_actions(linked_design(r),r)


def test_checker():
 r=target('main','AWS::WAFRegional::XssMatchSet',XssMatchTuples=[{'TextTransformation':'BASE64_DECODE'}]);root=Path(__file__).resolve().parents[1]
 found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='WAFREGIONAL_XSS_TRANSFORMATION' and f['verdict']=='FAIL' for f in found)
