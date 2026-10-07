from pathlib import Path
import pytest
from aws_design_sheet.checks.wafv2.association_and_logging import evaluate_wafv2_association_and_logging
from aws_design_sheet.checks.wellarchitected.lens_json_syntax import evaluate_wellarchitected_lens_json_syntax
from aws_design_sheet.checks.registry import combine
waf_links_checks = combine(evaluate_wafv2_association_and_logging, evaluate_wellarchitected_lens_json_syntax)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('case',['regional','cloudfront','unknown','default','external','conditional','duplicate'])
def test_scope(case):
 r=target('main','AWS::WAFv2::WebACLAssociation',WebACLArn='acl')
 a=target('acl','AWS::WAFv2::WebACL',**({} if case=='default' else {'Scope':UNKNOWN if case=='unknown' else 'CLOUDFRONT' if case=='cloudfront' else 'REGIONAL'}))
 links=[] if case=='external' else [('WebACLArn','acl')]*(2 if case=='duplicate' else 1)
 d=linked_design(r,[a],links)
 if case=='conditional':d.relations[0].condition='condition'
 assert waf_links_checks(d,r)[0]['verdict']==('PASS' if case=='regional' else 'FAIL' if case=='cloudfront' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind,key',[('AWS::Logs::LogGroup','LogGroupName'),('AWS::S3::Bucket','BucketName'),('AWS::KinesisFirehose::DeliveryStream','DeliveryStreamName')])
@pytest.mark.parametrize('case',['valid','invalid','unknown','generated','external','conditional'])
def test_log_name(kind,key,case):
 r=target('main','AWS::WAFv2::LoggingConfiguration',LogDestinationConfigs=['dest'])
 name=UNKNOWN if case=='unknown' else 'other-name' if case=='invalid' else 'aws-waf-logs-test'
 a=target('dest',kind,**({} if case=='generated' else {key:name}))
 d=linked_design(r,[a],[] if case=='external' else [('LogDestinationConfigs/0','dest')])
 if case=='conditional':d.relations[0].condition='condition'
 assert waf_links_checks(d,r)[0]['verdict']==('PASS' if case=='valid' else 'FAIL' if case=='invalid' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,expected',[('{}','PASS'),('null','PASS'),('{','FAIL'),('NaN','FAIL'),('${json}','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),(' '*256001,'NEEDS_REVIEW')],ids=['object','syntax_only','invalid','nan','dynamic','unknown','oversized'])
def test_json(raw,expected):
 r=target('main','AWS::WellArchitected::Lens',JSONString=raw)
 assert waf_links_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('kind',['AWS::WAFv2::WebACLAssociation','AWS::WAFv2::LoggingConfiguration','AWS::WellArchitected::Lens'])
def test_absent(kind):
 r=target('main',kind);assert not waf_links_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::WellArchitected::Lens',JSONString='{');root=Path(__file__).resolve().parents[1]
 found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='WELLARCHITECTED_LENS_JSON_SYNTAX' and f['verdict']=='FAIL' for f in found)
