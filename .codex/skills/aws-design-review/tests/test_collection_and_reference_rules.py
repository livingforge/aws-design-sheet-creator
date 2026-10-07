"""Design-decidable Tier 2 conditions with known and incomplete evidence."""
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_autoscaling_group_nested_constraints import design

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('schema,expected', [
    ({'properties': {'x': {'description': 'safe'}}}, 'PASS'),
    ({'properties': {'x': {'description': 'bad */ text'}}}, 'FAIL'),
    ({'items': [{'properties': {'x': {'description': '*/'}}}]}, 'FAIL'),
    ({'allOf': [{'definitions': {'x': {'description': '*/'}}}]}, 'FAIL'),
    ({'dependencies': {'x': {'description': '*/'}}}, 'FAIL'),
    ({'properties': {'description': {'type': 'string'}}}, 'PASS'),
    ({'default': {'description': '*/'}, 'enum': ['*/']}, 'PASS'),
    ({'properties': {'x': {'description': UNKNOWN}}}, 'NEEDS_REVIEW'),
    ({'properties': {'x': UNKNOWN}}, 'NEEDS_REVIEW'),
    ({'properties': {'x': {'$ref': '#/definitions/x'}}}, 'NEEDS_REVIEW'),
    ({'properties': {'x': UNKNOWN, 'y': {'description': '*/'}}}, 'FAIL'),
    ({'description': '{{resolve:ssm:test}}'}, 'NEEDS_REVIEW'),
    ({'additionalProperties': False, 'dependencies': {'x': ['y']}}, 'PASS'),
    ('{"properties":{"x":{"description":"*/"}}}', 'FAIL'),
    ('invalid JSON', 'NEEDS_REVIEW'),
    ({'Fn::Join': ['', ['schema']]}, 'NEEDS_REVIEW'),
    (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_model_sdk_description(schema, expected):
    resource = target('model', 'AWS::ApiGateway::Model', Schema=schema)
    result = rows(resource)['APIGATEWAY_MODEL_SDK_DESCRIPTION']
    assert result['verdict'] == expected
    assert result['severity'] == 'WARNING'


def test_model_sdk_description_absent_and_budget():
    resource = target('model', 'AWS::ApiGateway::Model')
    assert 'APIGATEWAY_MODEL_SDK_DESCRIPTION' not in rows(resource)
    resource = target('model', 'AWS::ApiGateway::Model', Schema={'allOf': [{}] * 10001})
    assert rows(resource)['APIGATEWAY_MODEL_SDK_DESCRIPTION']['verdict'] == 'NEEDS_REVIEW'


def test_model_sdk_description_checker():
    resource = target('model', 'AWS::ApiGateway::Model', Schema={'properties': {'x': {'description': '*/'}}})
    checked = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(design(resource))
    row = next(r for r in checked['results'] if r['rule_id'] == 'APIGATEWAY_MODEL_SDK_DESCRIPTION')
    assert row['verdict'] == 'FAIL' and row['severity'] == 'WARNING'
    assert row['source_urls'] and row['evidence_ids']


def rows(resource, data=None):
    return {r['rule_id']: r for r in run_resource_checks(data or design(resource), resource)}


@pytest.mark.parametrize('strategy,base,weight', [
    ([{'CapacityProvider': 'a', 'Weight': 1}, {'CapacityProvider': 'b'}], 'PASS', 'PASS'),
    ([{'CapacityProvider': 'a'}, {'CapacityProvider': 'b'}], 'PASS', 'FAIL'),
    ([{'Base': 0}, {'Base': 0, 'Weight': 1}], 'FAIL', 'PASS'),
    ([{'Base': UNKNOWN}, {'Weight': UNKNOWN}], 'NEEDS_REVIEW', 'NEEDS_REVIEW'),
    ([{'Base': 1, 'Weight': 1}, UNKNOWN], 'NEEDS_REVIEW', 'PASS'),
])
@pytest.mark.parametrize('kind', ['Service', 'TaskSet'])
def test_ecs_capacity(strategy, base, weight, kind):
    resource = target('svc', 'AWS::ECS::' + kind, CapacityProviderStrategy=strategy)
    values = rows(resource)
    assert values['ECS_CAPACITY_PROVIDER_BASE']['verdict'] == base
    assert values['ECS_CAPACITY_PROVIDER_WEIGHT']['verdict'] == weight


@pytest.mark.parametrize('mode,config,expected', [
    ('awsvpc', False, 'FAIL'), ('awsvpc', True, 'PASS'),
    ('bridge', False, 'PASS'), ('host', True, 'FAIL'),
    (UNKNOWN, True, 'NEEDS_REVIEW'),
])
def test_ecs_network(mode, config, expected):
    resource = target('svc', 'AWS::ECS::Service', TaskDefinition='task',
                      **({'NetworkConfiguration': {'AwsvpcConfiguration': {'Subnets': ['subnet']}}} if config else {}))
    task = target('task', 'AWS::ECS::TaskDefinition', NetworkMode=mode)
    data = linked_design(resource, [task], [('TaskDefinition', 'task')])
    assert rows(resource, data)['ECS_SERVICE_NETWORK_MODE']['verdict'] == expected


@pytest.mark.parametrize('count,unknown,expected', [(100, False, 'PASS'), (101, False, 'FAIL'),
                                                   (100, True, 'NEEDS_REVIEW'), (101, True, 'FAIL')])
def test_dynamodb_aggregate(count, unknown, expected):
    # Identical attribute names in different indexes still count separately.
    indexes = [{'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['repeated'] * 20}}
               for _ in range(count // 20)]
    if count % 20:
        indexes.append({'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['x'] * (count % 20)}})
    resource = target('table', 'AWS::DynamoDB::GlobalTable', GlobalSecondaryIndexes=indexes,
                      LocalSecondaryIndexes=[UNKNOWN] if unknown else [])
    assert rows(resource)['DYNAMODB_INDEX_PROJECTION_AGGREGATE']['verdict'] == expected


def test_dynamodb_regions():
    resource = target('table', 'AWS::DynamoDB::GlobalTable',
                      Replicas=[{'Region': 'us-east-1'}], GlobalTableWitnesses=[{'Region': 'us-east-1'}])
    values = rows(resource)
    assert values['DYNAMODB_GLOBAL_TABLE_DEPLOYMENT_REGION']['verdict'] == 'FAIL'
    assert values['DYNAMODB_GLOBAL_TABLE_WITNESS_REGION']['verdict'] == 'FAIL'
    resource.fields[0].selected().value.append({'Region': 'ap-northeast-1'})
    resource.fields[1].selected().value[0]['Region'] = 'us-east-2'
    assert rows(resource)['DYNAMODB_GLOBAL_TABLE_DEPLOYMENT_REGION']['verdict'] == 'PASS'
    assert rows(resource)['DYNAMODB_GLOBAL_TABLE_WITNESS_REGION']['verdict'] == 'PASS'


@pytest.mark.parametrize('protocol,expected', [('HTTP', 'FAIL'), ('SSL', 'PASS'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_classic_listener_same_port(protocol, expected):
    resource = target('lb', 'AWS::ElasticLoadBalancing::LoadBalancer', Listeners=[
        {'InstancePort': '443', 'InstanceProtocol': 'HTTPS', 'Protocol': 'HTTPS'},
        {'InstancePort': '443', 'InstanceProtocol': protocol, 'Protocol': 'HTTPS'}])
    assert rows(resource)['ELB_LISTENER_INSTANCE_PORT_PROTOCOL']['verdict'] == expected


@pytest.mark.parametrize('version,methods,expected', [
    ('http2', ['GET', 'POST'], 'PASS'), ('http1.1', ['GET', 'POST'], 'FAIL'),
    ('http2and3', ['GET'], 'FAIL'), (UNKNOWN, ['POST'], 'NEEDS_REVIEW'),
])
def test_cloudfront_grpc(version, methods, expected):
    resource = target('cdn', 'AWS::CloudFront::Distribution', DistributionConfig={
        'Origins': [{'Id': 'origin'}], 'HttpVersion': version,
        'DefaultCacheBehavior': {'TargetOriginId': 'origin', 'GrpcConfig': {'Enabled': True},
                                'AllowedMethods': methods}})
    values = rows(resource)
    assert values['CLOUDFRONT_GRPC_HTTP2_POST']['verdict'] == expected
    assert values['CLOUDFRONT_CACHE_TARGET_ORIGIN']['verdict'] == 'PASS'
    resource.fields[0].selected().value['DefaultCacheBehavior']['TargetOriginId'] = 'missing'
    assert rows(resource)['CLOUDFRONT_CACHE_TARGET_ORIGIN']['verdict'] == 'FAIL'
    resource.fields[0].selected().value['Origins'].append({'Id': 'origin'})
    assert rows(resource)['CLOUDFRONT_ORIGIN_IDS_UNIQUE']['verdict'] == 'FAIL'


@pytest.mark.parametrize('type,path,rule', [
    ('AWS::KMS::Alias', 'AliasName', 'KMS_ALIAS_DESIGN_NAME_UNIQUE'),
    ('AWS::SecretsManager::RotationSchedule', 'SecretId', 'SECRET_ROTATION_DESIGN_UNIQUE'),
    ('AWS::SecretsManager::SecretTargetAttachment', 'SecretId', 'SECRET_ATTACHMENT_DESIGN_UNIQUE'),
])
def test_duplicate_design_identities(type, path, rule):
    resource = target('a', type, **{path: 'same'})
    other = target('b', type, **{path: 'same'})
    data = linked_design(resource, [other])
    assert rows(resource, data)[rule]['verdict'] == 'FAIL'
    other.scope = other.scope.model_copy(update={'region': 'us-east-1'})
    assert rows(resource, data)[rule]['verdict'] == 'PASS'


def test_duplicate_resolved_secret_and_unknown_alias():
    resource = target('a', 'AWS::SecretsManager::RotationSchedule', SecretId='secret')
    other = target('b', resource.type, SecretId='another-label')
    secret = target('secret', 'AWS::SecretsManager::Secret')
    data = linked_design(resource, [other, secret], [('SecretId', 'secret')])
    data.relations.append(data.relations[0].model_copy(update={'id': 'other', 'source_resource_id': 'b'}))
    assert rows(resource, data)['SECRET_ROTATION_DESIGN_UNIQUE']['verdict'] == 'FAIL'
    data.relations.pop()
    assert rows(resource, data)['SECRET_ROTATION_DESIGN_UNIQUE']['verdict'] == 'NEEDS_REVIEW'


def test_key_signing_scope_and_checker():
    resource = target('a', 'AWS::Route53::KeySigningKey', Name='same', HostedZoneId='zone',
                      KeyManagementServiceArn='arn:key1')
    other = target('b', resource.type, Name='same', HostedZoneId='zone', KeyManagementServiceArn='arn:key2')
    data = linked_design(resource, [other])
    assert rows(resource, data)['ROUTE53_KEY_SIGNING_NAME_UNIQUE']['verdict'] == 'FAIL'
    assert rows(resource, data)['ROUTE53_KEY_SIGNING_KMS_UNIQUE']['verdict'] == 'PASS'
    checked = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(data)
    row = next(r for r in checked['results'] if r['rule_id'] == 'ROUTE53_KEY_SIGNING_NAME_UNIQUE')
    assert row['verdict'] == 'FAIL' and row['source_urls'] and row['evidence_ids']


@pytest.mark.parametrize('queries,ids,data', [
    ([{'Id': 'm', 'MetricStat': {}, 'ReturnData': False},
      {'Id': 'e', 'Expression': 'm', 'ReturnData': True}], 'PASS', 'PASS'),
    ([{'Id': 'm', 'ReturnData': True}, {'Id': 'm', 'ReturnData': False}], 'FAIL', 'PASS'),
    ([{'Id': 'm', 'ReturnData': True}, {'Id': UNKNOWN, 'ReturnData': UNKNOWN}], 'NEEDS_REVIEW', 'NEEDS_REVIEW'),
    ([{'Id': 'm', 'ReturnData': False}], 'PASS', 'FAIL'),
    ([{'Id': 'm', 'ReturnData': True}, {'Id': 'e', 'Expression': 'm', 'ReturnData': True}], 'PASS', 'FAIL'),
])
@pytest.mark.parametrize('kind', ['Alarm', 'AnomalyDetector'])
def test_cloudwatch_query_sets(queries, ids, data, kind):
    props = {'Metrics': queries} if kind == 'Alarm' else {'MetricMathAnomalyDetector': {'MetricDataQueries': queries}}
    resource = target('cw', 'AWS::CloudWatch::' + kind, **props)
    values = rows(resource)
    assert values['CLOUDWATCH_QUERY_IDS_UNIQUE']['verdict'] == ids
    assert values['CLOUDWATCH_QUERY_RETURN_DATA']['verdict'] == data


@pytest.mark.parametrize('actions,expected', [
    ([{'Type': 'forward'}], 'PASS'),
    ([{'Type': 'forward', 'Order': 2}, {'Type': 'authenticate-oidc', 'Order': 1}], 'PASS'),
    ([{'Type': 'forward', 'Order': 1}, {'Type': 'authenticate-oidc', 'Order': 2}], 'FAIL'),
    ([{'Type': 'forward'}, {'Type': 'fixed-response'}], 'FAIL'),
    ([{'Type': 'authenticate-oidc', 'Order': 1}], 'FAIL'),
    ([{'Type': 'forward', 'Order': 2}, UNKNOWN], 'NEEDS_REVIEW'),
])
def test_listener_action_execution_order(actions, expected):
    resource = target('rule', 'AWS::ElasticLoadBalancingV2::ListenerRule', Actions=actions)
    assert rows(resource)['ELBV2_RULE_TERMINAL_ACTION']['verdict'] == expected


def test_listener_protocol_and_attachment_type():
    resource = target('rule', 'AWS::ElasticLoadBalancingV2::ListenerRule', ListenerArn='listener',
                      Actions=[{'Type': 'authenticate-oidc', 'Order': 1},
                               {'Type': 'redirect', 'Order': 2, 'RedirectConfig': {'Protocol': 'HTTP'}}])
    listener = target('listener', 'AWS::ElasticLoadBalancingV2::Listener', Protocol='HTTPS')
    data = linked_design(resource, [listener], [('ListenerArn', 'listener')])
    assert rows(resource, data)['ELBV2_RULE_AUTH_HTTPS']['verdict'] == 'PASS'
    assert rows(resource, data)['ELBV2_RULE_REDIRECT_NO_DOWNGRADE']['verdict'] == 'FAIL'
    attachment = target('attach', 'AWS::SecretsManager::SecretTargetAttachment', TargetId='db',
                        TargetType='AWS::RDS::DBInstance')
    db = target('db', 'AWS::RDS::DBInstance')
    data = linked_design(attachment, [db], [('TargetId', 'db')])
    assert rows(attachment, data)['SECRET_ATTACHMENT_TARGET_TYPE']['verdict'] == 'PASS'
    db.type = 'AWS::RDS::DBCluster'
    assert rows(attachment, data)['SECRET_ATTACHMENT_TARGET_TYPE']['verdict'] == 'FAIL'


@pytest.mark.parametrize('period,expected', [(10, 'PASS'), (20, 'PASS'), (30, 'PASS'), (60, 'PASS'),
                                           (120, 'PASS'), (0, 'FAIL'), (45, 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_alarm_period(period, expected):
    resource = target('alarm', 'AWS::CloudWatch::Alarm', Period=period)
    assert rows(resource)['CLOUDWATCH_ALARM_PERIOD']['verdict'] == expected


@pytest.mark.parametrize('pattern,value,expected', [(r'^\d+$', '123', 'PASS'),
                                                  (r'^\d+$', 'abc', 'FAIL'),
                                                  ('[', 'abc', 'NEEDS_REVIEW'),
                                                  (UNKNOWN, 'abc', 'NEEDS_REVIEW')])
def test_ssm_pattern(pattern, value, expected):
    resource = target('param', 'AWS::SSM::Parameter', Type='String', Value=value, AllowedPattern=pattern)
    assert rows(resource)['SSM_PARAMETER_ALLOWED_PATTERN']['verdict'] == expected


def test_ssm_region():
    resource = target('sync', 'AWS::SSM::ResourceDataSync', S3Destination={
        'KMSKeyArn': 'arn:aws:kms:ap-northeast-1:111111111111:key/key', 'BucketRegion': 'ap-northeast-1'})
    assert rows(resource)['SSM_RESOURCE_DATA_SYNC_KMS_REGION']['verdict'] == 'PASS'
    resource.fields[0].selected().value['BucketRegion'] = 'us-east-1'
    assert rows(resource)['SSM_RESOURCE_DATA_SYNC_KMS_REGION']['verdict'] == 'FAIL'


@pytest.mark.parametrize('attributes,expected', [
    ([{'Key': 'access_logs.s3.enabled', 'Value': 'true'}], 'FAIL'),
    ([{'Key': 'access_logs.s3.enabled', 'Value': 'true'}, {'Key': 'access_logs.s3.bucket', 'Value': 'logs'}], 'PASS'),
    ([{'Key': 'access_logs.s3.enabled', 'Value': 'true'}, UNKNOWN], 'NEEDS_REVIEW'),
])
def test_log_bucket_attribute_dependencies(attributes, expected):
    resource = target('lb', 'AWS::ElasticLoadBalancingV2::LoadBalancer', LoadBalancerAttributes=attributes)
    assert rows(resource)['ELBV2_LOG_BUCKET_REQUIRED']['verdict'] == expected


def test_unknown_hosted_zones_do_not_prove_duplicate():
    first = target('first', 'AWS::Route53::KeySigningKey', Name='same', HostedZoneId=UNKNOWN)
    other = target('other', 'AWS::Route53::KeySigningKey', Name='same', HostedZoneId=UNKNOWN)
    data = linked_design(first, [other], [])
    assert rows(first, data)['ROUTE53_KEY_SIGNING_NAME_UNIQUE']['verdict'] == 'NEEDS_REVIEW'


def test_missing_backend_protocol_is_not_assumed():
    resource = target('lb', 'AWS::ElasticLoadBalancing::LoadBalancer', Listeners=[
        {'InstancePort': '443', 'Protocol': 'HTTPS'},
        {'InstancePort': '443', 'InstanceProtocol': 'HTTP', 'Protocol': 'HTTP'}])
    assert rows(resource)['ELB_LISTENER_INSTANCE_PORT_PROTOCOL']['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('kind', ['AWS::RedshiftServerless::Namespace', 'AWS::DocDBElastic::Cluster'])
def test_additional_secret_attachment_targets(kind):
    attachment = target('attachment', 'AWS::SecretsManager::SecretTargetAttachment',
                        TargetType=kind, TargetId='database')
    database = target('database', kind)
    data = linked_design(attachment, [database], [('TargetId', 'database')])
    assert rows(attachment, data)['SECRET_ATTACHMENT_TARGET_TYPE']['verdict'] == 'PASS'
