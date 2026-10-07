import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.config.key_region import config_key_region
from aws_design_sheet.checks.common.context_values import _Context
from test_autoscaling_group_and_scaling_policy import target,linked_design
from test_template_dependencies import link


@pytest.mark.parametrize('bucket_region,key_region,expected',[('ap-northeast-1','ap-northeast-1','PASS'),('us-east-1','us-east-1','PASS'),('us-east-1','ap-northeast-1','FAIL')])
@pytest.mark.parametrize('context',['local','account','conditional','source_template','bucket_template','unknown_scope'])
def test_config_key_destination_region(bucket_region,key_region,expected,context):
    r=target('main','AWS::Config::DeliveryChannel',S3BucketName='destination-bucket',S3KmsKeyArn='arn:aws:kms:'+key_region+':111111111111:key/example-key')
    b=target('bucket','AWS::S3::Bucket',BucketName='destination-bucket');b.scope.region=bucket_region
    d=linked_design(r,[b],[('S3BucketName','bucket')])
    if context=='account':b.scope.account='222222222222'
    if context=='conditional':d.relations[0].condition='maybe'
    if context=='source_template':r.template=TemplateContext(state='UNRESOLVED')
    if context=='bucket_template':b.template=TemplateContext(state='UNRESOLVED')
    if context=='unknown_scope':b.scope.region='UNKNOWN'
    assert config_key_region(_Context(d,r),r)==(expected if context in ('local','account') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['Key','ReplicaKey'])
def test_linked_key_region(kind):
    r=target('main','AWS::Config::DeliveryChannel',S3BucketName='bucket',S3KmsKeyArn='key')
    b=target('bucket','AWS::S3::Bucket');k=target('key','AWS::KMS::'+kind)
    d=linked_design(r,[b,k],[('S3BucketName','bucket'),('S3KmsKeyArn','key')])
    assert config_key_region(_Context(d,r),r)=='PASS'


@pytest.mark.parametrize('service',['WAF','WAFRegional'])
@pytest.mark.parametrize('raw',['EXACTLY','malformed'])
def test_waf_position_does_not_read_collection_as_enum(service,raw):
    from aws_design_sheet.checks.workspaces.volume_key_type import evaluate_workspaces_volume_key_type
    from aws_design_sheet.checks.workspacesweb.subnet_az_diversity import evaluate_workspacesweb_subnet_az_diversity
    from aws_design_sheet.checks.xray.policy_utf8_size import evaluate_xray_policy_utf8_size
    from aws_design_sheet.checks.waf.byte_position_and_sql import evaluate_waf_byte_position_and_sql, evaluate_wafregional_byte_position_and_sql
    from aws_design_sheet.checks.registry import combine
    queue_inputs_checks = combine(evaluate_workspaces_volume_key_type, evaluate_workspacesweb_subnet_az_diversity, evaluate_xray_policy_utf8_size, evaluate_waf_byte_position_and_sql, evaluate_wafregional_byte_position_and_sql)
    r=target('main','AWS::'+service+'::ByteMatchSet',ByteMatchTuples=raw)
    assert all(f['verdict']=='NEEDS_REVIEW' for f in queue_inputs_checks(linked_design(r),r))


def test_config_checker_dispatch_cross_region_bucket():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::Config::DeliveryChannel',S3BucketName='destination-bucket',S3KmsKeyArn='arn:aws:kms:us-east-1:111111111111:key/example-key')
    b=target('bucket','AWS::S3::Bucket',BucketName='destination-bucket');b.scope.region='us-east-1'
    d=linked_design(r,[b],[('S3BucketName','bucket')])
    assert any(f['rule_id']=='CONFIG_BUCKET_KMS_REGION' and f['verdict']=='PASS' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'])
