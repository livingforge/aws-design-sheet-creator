from pathlib import Path
import pytest
from aws_design_sheet.checks.workspaces.volume_key_type import evaluate_workspaces_volume_key_type
from aws_design_sheet.checks.workspacesweb.subnet_az_diversity import evaluate_workspacesweb_subnet_az_diversity
from aws_design_sheet.checks.xray.policy_utf8_size import evaluate_xray_policy_utf8_size
from aws_design_sheet.checks.waf.byte_position_and_sql import evaluate_waf_byte_position_and_sql, evaluate_wafregional_byte_position_and_sql
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
queue_inputs_checks = combine(evaluate_workspaces_volume_key_type, evaluate_workspacesweb_subnet_az_diversity, evaluate_xray_policy_utf8_size, evaluate_waf_byte_position_and_sql, evaluate_wafregional_byte_position_and_sql)


@pytest.mark.parametrize('case',['symmetric','asymmetric','hmac','default','unknown','external','conditional','disabled'])
def test_key(case):
 r=target('main','AWS::WorkSpaces::Workspace',RootVolumeEncryptionEnabled=case!='disabled',VolumeEncryptionKey='key')
 spec='RSA_2048' if case=='asymmetric' else 'HMAC_256' if case=='hmac' else UNKNOWN if case=='unknown' else 'SYMMETRIC_DEFAULT'
 k=target('key','AWS::KMS::Key',**({} if case=='default' else {'KeySpec':spec}))
 d=linked_design(r,[k],[] if case=='external' else [('VolumeEncryptionKey','key')])
 if case=='conditional':d.relations[0].condition='condition'
 assert queue_inputs_checks(d,r)[0]['verdict']==('PASS' if case in ('symmetric','default') else 'FAIL' if case in ('asymmetric','hmac') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('case',['distinct','same','unknown','default','external','conditional','az_id','single','unknown_list'])
def test_az(case):
 r=target('main','AWS::WorkSpacesWeb::NetworkSettings',SubnetIds=UNKNOWN if case=='unknown_list' else ['a'] if case=='single' else ['a','b'])
 a=target('a','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a')
 az=UNKNOWN if case=='unknown' else 'apne1-az1' if case=='az_id' else 'ap-northeast-1a' if case=='same' else 'ap-northeast-1c'
 b=target('b','AWS::EC2::Subnet',**({} if case=='default' else {'AvailabilityZone':az}))
 d=linked_design(r,[a,b],[('SubnetIds/0','a')]+([] if case=='external' else [('SubnetIds/1','b')]))
 if case=='conditional':d.relations[1].condition='condition'
 assert queue_inputs_checks(d,r)[0]['verdict']==('PASS' if case=='distinct' else 'FAIL' if case=='same' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,expected',[('a'*5000,'PASS'),('a'*5001,'NEEDS_REVIEW'),('a'*5120,'NEEDS_REVIEW'),('a'*5121,'FAIL'),('\u3042'*1707,'FAIL'),('\u3042'*1000,'PASS'),('\ud800','NEEDS_REVIEW'),('${policy}','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')],ids=['decimal_limit','ambiguous_low','ambiguous_high','over','multibyte_over','multibyte_ok','surrogate','dynamic','unknown'])
def test_bytes(raw,expected):
 r=target('main','AWS::XRay::ResourcePolicy',PolicyDocument=raw)
 assert queue_inputs_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('namespace',['WAF','WAFRegional'])
@pytest.mark.parametrize('raw,expected',[('CONTAINS','PASS'),('CONTAINS_WORD','PASS'),('EXACTLY','PASS'),('STARTS_WITH','PASS'),('ENDS_WITH','PASS'),('contains','FAIL'),('OTHER','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_positions(namespace,raw,expected):
 r=target('main','AWS::'+namespace+'::ByteMatchSet',ByteMatchTuples=[{'PositionalConstraint':raw}])
 assert queue_inputs_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('raw,expected',[('NONE','PASS'),('COMPRESS_WHITE_SPACE','PASS'),('HTML_ENTITY_DECODE','PASS'),('LOWERCASE','PASS'),('CMD_LINE','PASS'),('URL_DECODE','PASS'),('BASE64_DECODE','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_sql(raw,expected):
 r=target('main','AWS::WAFRegional::SqlInjectionMatchSet',SqlInjectionMatchTuples=[{'TextTransformation':raw}])
 assert queue_inputs_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('kind',['AWS::WorkSpaces::Workspace','AWS::WorkSpacesWeb::NetworkSettings','AWS::XRay::ResourcePolicy','AWS::WAF::ByteMatchSet','AWS::WAFRegional::ByteMatchSet','AWS::WAFRegional::SqlInjectionMatchSet'])
def test_absent(kind):
 r=target('main',kind);assert not queue_inputs_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::XRay::ResourcePolicy',PolicyDocument='\u3042'*1707);root=Path(__file__).resolve().parents[1]
 found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='XRAY_POLICY_UTF8_SIZE' and f['verdict']=='FAIL' for f in found)
