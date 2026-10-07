from pathlib import Path
import pytest
from aws_design_sheet.checks.waf.ip_and_action_types import evaluate_waf_ip_and_action_types
from aws_design_sheet.checks.supportauthz.signing_key_settings import evaluate_supportauthz_signing_key_settings
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
classic_values_checks=combine(evaluate_waf_ip_and_action_types,evaluate_supportauthz_signing_key_settings)


@pytest.mark.parametrize('raw,expected',[('IPV4','PASS'),('IPV6','PASS'),('IPv4','FAIL'),('OTHER','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${type}','NEEDS_REVIEW')])
def test_ip(raw,expected):
 r=target('main','AWS::WAF::IPSet',IPSetDescriptors=[{'Type':raw}])
 assert classic_values_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('raw,expected',[('ALLOW','PASS'),('BLOCK','PASS'),('COUNT','PASS'),('allow','FAIL'),('CAPTCHA','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_action(raw,expected):
 r=target('main','AWS::WAF::WebACL',Rules=[{'Action':{'Type':raw}}])
 assert classic_values_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('case',['match','wrong_spec','wrong_usage','unknown','default','external','conditional','duplicate','wrong_type'])
def test_key(case):
 r=target('main','AWS::SupportAuthZ::SupportPermit',SigningKeyInfo={'KmsKey':'key'})
 props={} if case=='default' else {'KeySpec':UNKNOWN if case=='unknown' else 'RSA_2048' if case=='wrong_spec' else 'ECC_NIST_P384','KeyUsage':'ENCRYPT_DECRYPT' if case=='wrong_usage' else 'SIGN_VERIFY'}
 k=target('key','AWS::S3::Bucket' if case=='wrong_type' else 'AWS::KMS::Key',**props)
 links=[] if case=='external' else [('SigningKeyInfo/KmsKey','key')]*(2 if case=='duplicate' else 1)
 d=linked_design(r,[k],links)
 if case=='conditional':d.relations[0].condition='condition'
 assert classic_values_checks(d,r)[0]['verdict']==('PASS' if case=='match' else 'FAIL' if case in ('wrong_spec','wrong_usage','default') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind,key',[('AWS::WAF::IPSet','IPSetDescriptors'),('AWS::WAF::WebACL','Rules')])
def test_unknown_collection(kind,key):
 r=target('main',kind,**{key:UNKNOWN});found=classic_values_checks(linked_design(r),r)
 assert len(found)==1 and found[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('kind',['AWS::WAF::IPSet','AWS::WAF::WebACL','AWS::SupportAuthZ::SupportPermit'])
def test_absent(kind):
 r=target('main',kind);assert not classic_values_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::WAF::IPSet',IPSetDescriptors=[{'Type':'OTHER'}]);root=Path(__file__).resolve().parents[1]
 found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='WAF_CLASSIC_IP_DESCRIPTOR_TYPE' and f['verdict']=='FAIL' for f in found)
