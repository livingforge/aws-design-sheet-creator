import json
import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(resource, others=()):
    return {r['rule_id']: r['verdict'] for r in run_resource_checks(linked_design(resource, others), resource)}


@pytest.mark.parametrize('kind', ['Key', 'ReplicaKey'])
@pytest.mark.parametrize('policy,expected', [
    ({'Statement': [{'Principal': '*'}]}, 'PASS'),
    ({'Statement': {'Principal': {'AWS': ['arn:aws:iam::111111111111:root']}}}, 'PASS'),
    ({'Statement': [{'Action': 'kms:*'}]}, 'FAIL'),
    ({'Statement': [{'Principal': {}}]}, 'FAIL'),
    ({'Statement': [{'Principal': {'AWS': []}}]}, 'FAIL'),
    ({'Statement': [{'Principal': {'AWS': UNKNOWN}}]}, 'NEEDS_REVIEW'),
    ({'Statement': [{'NotPrincipal': {'AWS': 'arn'}}]}, 'NEEDS_REVIEW'),
    (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_principal_presence(kind, policy, expected):
    resource = target('key', 'AWS::KMS::'+kind, KeyPolicy=policy)
    assert check(resource)['KMS_POLICY_PRINCIPALS_PRESENT'] == expected


@pytest.mark.parametrize('raw,expected', [
    (json.dumps({'Statement': [{'Principal': '*'}]}), 'PASS'), ('{', 'FAIL'), ('NaN', 'FAIL'),
    ('{{resolve:ssm:policy}}', 'NEEDS_REVIEW'),
])
def test_json_policy(raw, expected):
    assert check(target('key', 'AWS::KMS::Key', KeyPolicy=raw))['KMS_POLICY_PRINCIPALS_PRESENT'] == expected


@pytest.mark.parametrize('region,expected', [('cn-north-1', 'PASS'), ('cn-northwest-1', 'PASS'),
    ('us-east-1', 'FAIL'), ('us-gov-west-1', 'FAIL'), ('unknown', 'NEEDS_REVIEW')])
def test_sm2_region(region, expected):
    resource = target('key', 'AWS::KMS::Key', KeySpec='SM2'); resource.scope.region=region
    assert check(resource)['KMS_SM2_CHINA_REGION'] == expected


@pytest.mark.parametrize('partition,region,expected', [('aws', 'us-east-1', 'PASS'),
    ('aws', 'ap-northeast-1', 'FAIL'), ('aws-cn', 'cn-north-1', 'FAIL')])
def test_replica_region_and_partition(partition, region, expected):
    resource = target('replica', 'AWS::KMS::ReplicaKey', PrimaryKeyArn=f'arn:{partition}:kms:{region}:111111111111:key/mrk-example')
    resource.scope.region='ap-northeast-1'
    assert check(resource)['KMS_REPLICA_REGION_PARTITION'] == expected


def test_replica_duplicate_only_same_account_region():
    arn='arn:aws:kms:us-east-1:111111111111:key/mrk-example'
    resource=target('a', 'AWS::KMS::ReplicaKey', PrimaryKeyArn=arn)
    other=target('b', 'AWS::KMS::ReplicaKey', PrimaryKeyArn=arn)
    assert check(resource,[other])['KMS_REPLICA_DESIGN_DUPLICATE']=='FAIL'
    other.scope.region='us-west-2'
    assert check(resource,[other])['KMS_REPLICA_DESIGN_DUPLICATE']=='NEEDS_REVIEW'
