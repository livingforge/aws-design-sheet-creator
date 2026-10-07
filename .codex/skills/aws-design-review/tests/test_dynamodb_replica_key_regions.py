import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('key,region,expected', [
    ('arn:aws:kms:us-east-1:111111111111:key/test', 'us-east-1', 'PASS'),
    ('arn:aws:kms:us-east-1:111111111111:alias/test', 'us-west-2', 'FAIL'),
    ('arn:aws-cn:kms:cn-north-1:111111111111:key/test', 'cn-north-1', 'PASS'),
    ('alias/test', 'us-east-1', 'NEEDS_REVIEW'),
    ('key-id', 'us-east-1', 'NEEDS_REVIEW'),
    (UNKNOWN, 'us-east-1', 'NEEDS_REVIEW'),
    ('arn:aws:kms:us-east-1:111111111111:key/test', UNKNOWN, 'NEEDS_REVIEW'),
    ('arn:aws:kms:us-east-1:111111111111:key/test', '{{region}}', 'NEEDS_REVIEW'),
])
def test_replica_key_region(key, region, expected):
    resource = target('table', 'AWS::DynamoDB::GlobalTable', Replicas=[
        {'Region': region, 'SSESpecification': {'KMSMasterKeyId': key}}])
    findings = {r['rule_id']: r['verdict'] for r in run_resource_checks(linked_design(resource), resource)}
    assert findings['DYNAMODB_REPLICA_KMS_REGION'] == expected


def test_default_encryption_has_no_region_finding():
    resource = target('table', 'AWS::DynamoDB::GlobalTable', Replicas=[{'Region': 'us-east-1'}])
    assert not any(r['rule_id'] == 'DYNAMODB_REPLICA_KMS_REGION' for r in run_resource_checks(linked_design(resource), resource))
