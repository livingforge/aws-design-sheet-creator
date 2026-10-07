import pytest
from aws_design_sheet.checks.config.conformance_template import content, evaluate_config_conformance_template
from aws_design_sheet.models import TemplateContext
from test_autoscaling_group_and_scaling_policy import target,linked_design


@pytest.mark.parametrize('raw,expected',[
 ('Resources:\n  Rule:\n    Type: AWS::Config::ConfigRule','PASS'),
 ('Resources:\n  Fix:\n    Type: AWS::Config::RemediationConfiguration','PASS'),
 ('Resources:\n  Rule:\n    Type: AWS::S3::Bucket','FAIL'),
 ('Resources:\n  Rule:\n    Type: AWS::S3::Bucket\n    Condition: Maybe','NEEDS_REVIEW'),
 ('Resources:\n  Rule:\n    Type: !Ref ResourceType','NEEDS_REVIEW'),
 ('Resources:\n  Rule:\n    Type: AWS::Config::ConfigRule\n    Properties:\n      InputParameters: !Sub "${Input}"','PASS'),
 ('Transform: SomeMacro\nResources:\n  Rule:\n    Type: AWS::Config::ConfigRule','NEEDS_REVIEW'),
 ('Resources:\n  Rule: &item\n    Type: AWS::Config::ConfigRule\n  Other: *item','NEEDS_REVIEW'),
 ('Resources:\n  Rule:\n    Type: AWS::Config::ConfigRule\n    Type: AWS::S3::Bucket','NEEDS_REVIEW'),
 ('Resources:\n  Rule:\n    Type: AWS::Config::ConfigRule\nResources: {}','NEEDS_REVIEW'),
 ('Resources: {}','NEEDS_REVIEW'),('Resources: [','NEEDS_REVIEW'),
 ('!!python/object/apply:os.system ["echo should-never-run"]','NEEDS_REVIEW'),
 ('Resources: {}\n---\nResources: {}','NEEDS_REVIEW'),
 ({'$state':'UNRESOLVED'},'NEEDS_REVIEW'),('', 'FAIL'),
 ])
def test_resource_types_and_nonexecuting_parser(raw,expected):
    assert content(raw)==expected


@pytest.mark.parametrize('bytes_extra,expected',[(0,'PASS'),(1,'FAIL')])
def test_utf8_byte_boundary(bytes_extra,expected):
    base='Resources:\n  Rule:\n    Type: AWS::Config::ConfigRule\n# '
    padding=51200-len(base.encode())
    raw=base+'界'*(padding//3)+'x'*(padding%3+bytes_extra)
    assert content(raw)==expected


def test_unresolved_template_scope():
    r=target('main','AWS::Config::ConformancePack',TemplateBody='Resources:\n  Bad:\n    Type: AWS::S3::Bucket');r.template=TemplateContext(state='UNRESOLVED')
    assert evaluate_config_conformance_template(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


def test_absent_body_does_not_fetch_s3():
    r=target('main','AWS::Config::ConformancePack',TemplateS3Uri='s3://private/template.yaml')
    assert evaluate_config_conformance_template(linked_design(r),r)==[]


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::Config::ConformancePack',TemplateBody='Resources:\n  Bad:\n    Type: AWS::S3::Bucket')
    assert any(f['rule_id']=='CONFIG_CONFORMANCE_TEMPLATE_CONTENT' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
