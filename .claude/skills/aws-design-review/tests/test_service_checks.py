import json
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_autoscaling_group_nested_constraints import design

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('kind', ['MaintenanceWindowTarget', 'MaintenanceWindowTask'])
@pytest.mark.parametrize('key,expected', [
    ('tag:Environment', 'PASS'), ('tag:\u74b0\u5883', 'PASS'), ('tag:\u00a0\u2163', 'PASS'),
    ('invalid!key', 'FAIL'), ('tag:x\n', 'FAIL'), ('tag:e\u0301', 'FAIL'),
    (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_ssm_unicode_target_key(kind, key, expected):
    resource = target('target', 'AWS::SSM::' + kind, Targets=[{'Key': key}])
    assert check(resource, 'SSM_TARGET_KEY_CHARACTERS')[0]['verdict'] == expected


def check(resource, rule):
    return [r for r in run_resource_checks(design(resource), resource) if r['rule_id'] == rule]


@pytest.mark.parametrize('fmt,values,expected', [
    ('space-separated-values', ['read', 'write'], 'PASS'),
    ('space-separated-values', ['read write'], 'FAIL'),
    ('space-separated-values', [' read'], 'FAIL'),
    ('space-separated-values', [UNKNOWN], 'NEEDS_REVIEW'),
    ('space-separated-values', ['read write', UNKNOWN], 'FAIL'),
    ('space-separated-values', ['{{resolve:ssm:claim}}'], 'NEEDS_REVIEW'),
    (UNKNOWN, ['read write'], 'NEEDS_REVIEW'),
    ('single-string', ['read write'], None), ('string-array', ['read write'], None),
])
def test_jwt_claim_spaces(fmt, values, expected):
    resource = target('rule', 'AWS::ElasticLoadBalancingV2::ListenerRule', Actions=[{
        'Type': 'jwt-validation', 'JwtValidationConfig': {'AdditionalClaims': [{'Format': fmt, 'Values': values}]}}])
    result = check(resource, 'ELBV2_JWT_CLAIM_SPACES')
    assert (result[0]['verdict'] if result else None) == expected


@pytest.mark.parametrize('kind,key,expected', [
    ('network', 'connection_logs.s3.enabled', 'FAIL'),
    ('gateway', 'access_logs.s3.bucket', 'FAIL'),
    ('application', 'dns_record.client_routing_policy', 'FAIL'),
    ('network', 'dns_record.client_routing_policy', 'PASS'),
    (UNKNOWN, 'access_logs.s3.bucket', 'NEEDS_REVIEW'),
    ('application', 'new.future.attribute', 'NEEDS_REVIEW'),
    ('application', UNKNOWN, 'NEEDS_REVIEW'),
])
def test_lb_examples(kind, key, expected):
    resource = target('lb', 'AWS::ElasticLoadBalancingV2::LoadBalancer', Type=kind,
                      LoadBalancerAttributes=[{'Key': key, 'Value': 'false'}])
    assert check(resource, 'ELBV2_ATTRIBUTE_TYPE')[0]['verdict'] == expected


@pytest.mark.parametrize('flag,expected', [('true', 'PASS'), ('false', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_alb_default_and_cross_zone(flag, expected):
    resource = target('lb', 'AWS::ElasticLoadBalancingV2::LoadBalancer',
                      LoadBalancerAttributes=[{'Key': 'load_balancing.cross_zone.enabled', 'Value': flag}])
    assert check(resource, 'ELBV2_ALB_CROSS_ZONE')[0]['verdict'] == expected


@pytest.mark.parametrize('mode,forward,expected', [('tenant-only', {}, 'FAIL'),
    ('tenant-only', UNKNOWN, 'NEEDS_REVIEW'), (UNKNOWN, {}, 'NEEDS_REVIEW'), ('direct', {}, None)])
@pytest.mark.parametrize('location', ['DefaultCacheBehavior', 'CacheBehaviors'])
def test_tenant_forwarding(mode, forward, expected, location):
    behavior = {'ForwardedValues': forward}
    resource = target('cf', 'AWS::CloudFront::Distribution', DistributionConfig={
        'ConnectionMode': mode, location: [behavior] if location == 'CacheBehaviors' else behavior})
    results = check(resource, 'CLOUDFRONT_TENANT_FORWARDED_VALUES')
    assert (results[0]['verdict'] if results else None) == expected


@pytest.mark.parametrize('region,partition', [('ap-northeast-1', 'aws'), ('cn-north-1', 'aws-cn'),
                                            ('us-gov-west-1', 'aws-us-gov')])
@pytest.mark.parametrize('slash', ['', '/'])
@pytest.mark.parametrize('extra,expected', [(0, 'PASS'), (1, 'FAIL')])
def test_ssm_length_boundary(region, partition, slash, extra, expected):
    account = '111111111111'
    budget = 1011 - len(f'arn:{partition}:ssm:{region}:{account}:parameter/')
    resource = target('param', 'AWS::SSM::Parameter', Name=slash + 'a' * (budget + extra))
    resource.scope.region, resource.scope.account = region, account
    assert check(resource, 'SSM_PARAMETER_ARN_LENGTH')[0]['verdict'] == expected


@pytest.mark.parametrize('region,account,name', [('us-iso-east-1', '111111111111', 'name'),
    ('ap-northeast-1', 'unknown', 'name'), ('ap-northeast-1', '111111111111', UNKNOWN)])
def test_ssm_length_unresolved(region, account, name):
    resource = target('param', 'AWS::SSM::Parameter', Name=name)
    resource.scope.region, resource.scope.account = region, account
    assert check(resource, 'SSM_PARAMETER_ARN_LENGTH')[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('policies,expected', [('[]', 'PASS'), ('[{}]', 'PASS'),
    (json.dumps([{}] * 10), 'PASS'), (json.dumps([{}] * 11), 'FAIL'), ('{}', 'FAIL'),
    ('bad json', 'FAIL'), ('[NaN]', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW'), ('{{resolve:ssm:policy}}', 'NEEDS_REVIEW')])
def test_ssm_policy_array(policies, expected):
    resource = target('param', 'AWS::SSM::Parameter', Policies=policies)
    assert check(resource, 'SSM_PARAMETER_POLICY_ARRAY')[0]['verdict'] == expected


def test_checker_sources():
    resource = target('lb', 'AWS::ElasticLoadBalancingV2::LoadBalancer', Type='gateway',
                      LoadBalancerAttributes=[{'Key': 'access_logs.s3.enabled', 'Value': 'false'}])
    checked = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(design(resource))
    result = next(r for r in checked['results'] if r['rule_id'] == 'ELBV2_ATTRIBUTE_TYPE')
    assert result['verdict'] == 'FAIL' and result['source_urls'] and result['evidence_ids']


@pytest.mark.parametrize('properties,expected', [({}, 'FAIL'), ({'MetricName': 'CPU'}, 'PASS'),
    ({'Metrics': []}, 'PASS'), ({'MetricName': 'CPU', 'Metrics': []}, 'FAIL'),
    ({'MetricName': UNKNOWN}, 'NEEDS_REVIEW'), ({'EvaluationCriteria': {}}, 'PASS')])
def test_alarm_source(properties, expected):
    resource = target('alarm', 'AWS::CloudWatch::Alarm', **properties)
    assert check(resource, 'CLOUDWATCH_ALARM_SOURCE')[0]['verdict'] == expected


@pytest.mark.parametrize('properties,expected', [({'EvaluationInterval': 60}, 'PASS'),
    ({}, 'FAIL'), ({'EvaluationInterval': 61}, 'FAIL'), ({'EvaluationInterval': 3601}, 'FAIL'),
    ({'EvaluationInterval': 10, 'Threshold': 1}, 'FAIL'),
    ({'EvaluationInterval': UNKNOWN}, 'NEEDS_REVIEW')])
def test_promql_properties(properties, expected):
    resource = target('alarm', 'AWS::CloudWatch::Alarm', EvaluationCriteria={}, **properties)
    assert check(resource, 'CLOUDWATCH_PROMQL_PROPERTIES')[0]['verdict'] == expected


@pytest.mark.parametrize('definitions,key,expected', [([{'AttributeName': 'pk'}], 'pk', 'PASS'),
    ([{'AttributeName': 'pk'}], 'sk', 'FAIL'), ([UNKNOWN], 'sk', 'NEEDS_REVIEW'),
    ([{'AttributeName': 'pk'}], UNKNOWN, 'NEEDS_REVIEW')])
@pytest.mark.parametrize('kind', ['Table', 'GlobalTable'])
def test_dynamodb_key_definitions(definitions, key, expected, kind):
    resource = target('table', 'AWS::DynamoDB::' + kind, AttributeDefinitions=definitions,
        KeySchema=[{'AttributeName': key, 'KeyType': 'HASH'}])
    assert check(resource, 'DYNAMODB_KEY_ATTRIBUTE_DEFINED')[0]['verdict'] == expected


@pytest.mark.parametrize('local,expected', [('same', 'FAIL'), ('different', 'PASS'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_combined_index_names(local, expected):
    resource = target('table', 'AWS::DynamoDB::Table',
        GlobalSecondaryIndexes=[{'IndexName': 'same'}], LocalSecondaryIndexes=[{'IndexName': local}])
    assert check(resource, 'DYNAMODB_INDEX_NAMES_COMBINED')[0]['verdict'] == expected


@pytest.mark.parametrize('regions,witness,expected', [
    (['us-east-1', 'us-east-2'], 'us-west-2', 'PASS'),
    (['eu-west-1', 'eu-west-2'], 'eu-central-1', 'PASS'),
    (['us-east-1', 'eu-west-1'], 'us-west-2', 'FAIL'),
    (['us-east-1', UNKNOWN], 'us-west-2', 'NEEDS_REVIEW'),
    (['new-future-1', 'new-future-2'], 'new-future-3', 'NEEDS_REVIEW'),
])
def test_mrsc_region_sets(regions, witness, expected):
    resource = target('table', 'AWS::DynamoDB::GlobalTable', MultiRegionConsistency='STRONG',
        Replicas=[{'Region': r} for r in regions], GlobalTableWitnesses=[{'Region': witness}])
    assert check(resource, 'DYNAMODB_MRSC_REGION_SET')[0]['verdict'] == expected


@pytest.mark.parametrize('containers,expected', [([{'Name': 'app'}], 'PASS'),
    ([{'Essential': False}], 'FAIL'), ([{'Essential': False}, UNKNOWN], 'NEEDS_REVIEW'),
    ([{'Essential': True}, UNKNOWN], 'PASS'), ([], 'FAIL')])
def test_ecs_essential(containers, expected):
    resource = target('task', 'AWS::ECS::TaskDefinition', ContainerDefinitions=containers)
    assert check(resource, 'ECS_TASK_ESSENTIAL_CONTAINER')[0]['verdict'] == expected


@pytest.mark.parametrize('flags,expected', [([True, True], 'FAIL'), ([True, False], 'PASS'),
    ([True, UNKNOWN], 'NEEDS_REVIEW'), ([True, True, UNKNOWN], 'FAIL')])
def test_launch_volume_count(flags, expected):
    resource = target('task', 'AWS::ECS::TaskDefinition', Volumes=[{'ConfiguredAtLaunch': f} for f in flags])
    assert check(resource, 'ECS_TASK_LAUNCH_VOLUME_COUNT')[0]['verdict'] == expected


@pytest.mark.parametrize('condition,props,expected', [
    ('COMPLETE', {'Essential': False}, 'PASS'), ('COMPLETE', {}, 'FAIL'),
    ('SUCCESS', {'Essential': True}, 'FAIL'), ('SUCCESS', {'Essential': UNKNOWN}, 'NEEDS_REVIEW'),
    ('HEALTHY', {'HealthCheck': {'Command': ['CMD', 'true']}}, 'PASS'),
    ('HEALTHY', {}, 'FAIL'), ('HEALTHY', {'HealthCheck': UNKNOWN}, 'NEEDS_REVIEW'), ('START', {}, 'PASS')])
def test_ecs_dependency_target(condition, props, expected):
    resource = target('task', 'AWS::ECS::TaskDefinition', ContainerDefinitions=[
        {'Name': 'app', 'DependsOn': [{'ContainerName': 'setup', 'Condition': condition}]},
        {'Name': 'setup', **props}])
    assert check(resource, 'ECS_TASK_DEPENDENCY_TARGET')[0]['verdict'] == expected


@pytest.mark.parametrize('targets,expected', [([], 'FAIL'), ([UNKNOWN], 'NEEDS_REVIEW'),
    ([{'Name': 'setup'}, {'Name': 'setup'}], 'NEEDS_REVIEW')])
def test_ecs_dependency_unresolved(targets, expected):
    resource = target('task', 'AWS::ECS::TaskDefinition', ContainerDefinitions=[
        {'Name': 'app', 'DependsOn': [{'ContainerName': 'setup', 'Condition': 'START'}]}, *targets])
    assert check(resource, 'ECS_TASK_DEPENDENCY_TARGET')[0]['verdict'] == expected


@pytest.mark.parametrize('volumes,expected', [([{'Name': 'data'}], 'PASS'),
    ([{'Name': 'other'}], 'FAIL'), ([UNKNOWN], 'NEEDS_REVIEW')])
def test_ecs_mount_volume(volumes, expected):
    resource = target('task', 'AWS::ECS::TaskDefinition', Volumes=volumes,
        ContainerDefinitions=[{'Name': 'app', 'MountPoints': [{'SourceVolume': 'data'}]}])
    assert check(resource, 'ECS_TASK_MOUNT_VOLUME')[0]['verdict'] == expected


@pytest.mark.parametrize('name,source,expected', [('aws.partner/p/x', 'aws.partner/p/x', 'PASS'),
    ('other', 'aws.partner/p/x', 'FAIL'), (UNKNOWN, 'aws.partner/p/x', 'NEEDS_REVIEW')])
def test_partner_bus(name, source, expected):
    resource = target('bus', 'AWS::Events::EventBus', Name=name, EventSourceName=source)
    assert check(resource, 'EVENTS_PARTNER_BUS_NAME')[0]['verdict'] == expected


@pytest.mark.parametrize('fields,expected', [(['host-header', 'host-header'], 'FAIL'),
    (['http-header', 'http-header'], 'PASS'), (['path-pattern', UNKNOWN], 'NEEDS_REVIEW'),
    (['source-ip', 'source-ip', UNKNOWN], 'FAIL')])
def test_listener_condition_counts(fields, expected):
    resource = target('rule', 'AWS::ElasticLoadBalancingV2::ListenerRule', Conditions=[{'Field': f} for f in fields])
    assert check(resource, 'ELBV2_SINGLETON_CONDITIONS')[0]['verdict'] == expected


@pytest.mark.parametrize('name,expected', [('*.example.com', 'PASS'), ('localhost', 'FAIL'),
    ('example.123', 'FAIL'), ('example.*', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_listener_host_value(name, expected):
    resource = target('rule', 'AWS::ElasticLoadBalancingV2::ListenerRule',
        Conditions=[{'Field': 'host-header', 'HostHeaderConfig': {'Values': [name]}}])
    assert check(resource, 'ELBV2_HOST_HEADER_VALUES')[0]['verdict'] == expected


@pytest.mark.parametrize('groups,expected', [([{'TargetGroupArn': 'arn:a'}], 'PASS'),
    ([{'TargetGroupArn': 'arn:b'}], 'FAIL'), ([], 'FAIL'), ([{'TargetGroupArn': UNKNOWN}], 'NEEDS_REVIEW')])
def test_forward_target_match(groups, expected):
    resource = target('rule', 'AWS::ElasticLoadBalancingV2::ListenerRule',
        Actions=[{'Type': 'forward', 'TargetGroupArn': 'arn:a', 'ForwardConfig': {'TargetGroups': groups}}])
    assert check(resource, 'ELBV2_FORWARD_TARGET_MATCH')[0]['verdict'] == expected


@pytest.mark.parametrize('mappings,expected', [
    ([{'ContainerPortRange': '1-65535'}], 'PASS'),
    ([{'ContainerPortRange': '80-80'}], 'FAIL'),
    ([{'ContainerPortRange': '0-100'}], 'FAIL'),
    ([{'ContainerPortRange': '100-65536'}], 'FAIL'),
    ([{'ContainerPortRange': '90-80'}], 'FAIL'),
    ([{'ContainerPortRange': '1-80'}, {'ContainerPortRange': '81-100'}], 'PASS'),
    ([{'ContainerPortRange': '1-80'}, {'ContainerPortRange': '80-100'}], 'FAIL'),
    ([{'ContainerPortRange': '1-80'}, {'ContainerPort': 80}], 'FAIL'),
    ([{'ContainerPort': 80}, {'ContainerPort': 80, 'Protocol': 'udp'}], 'FAIL'),
    ([{'ContainerPortRange': UNKNOWN}], 'NEEDS_REVIEW'),
    ([{'ContainerPortRange': '1-10'}, {'ContainerPortRange': '5-20'}, UNKNOWN], 'FAIL'),
    ([{'ContainerPortRange': '1-10', 'ContainerPort': 1}], 'NEEDS_REVIEW'),
    ([{'ContainerPortRange': f'{i*2+1}-{i*2+2}'} for i in range(100)], 'PASS'),
    ([{'ContainerPortRange': f'{i*2+1}-{i*2+2}'} for i in range(101)], 'FAIL'),
])
def test_ecs_port_ranges(mappings, expected):
    resource = target('task', 'AWS::ECS::TaskDefinition', ContainerDefinitions=[{'PortMappings': mappings}])
    assert check(resource, 'ECS_TASK_PORT_RANGES')[0]['verdict'] == expected


@pytest.mark.parametrize('account,expected', [('111111111111', 'PASS'), ('222222222222', 'FAIL')])
def test_ecr_arn_account(account, expected):
    resource = target('cache', 'AWS::ECR::PullThroughCacheRule', CustomRoleArn=f'arn:aws:iam::{account}:role/cache')
    resource.scope.account = '111111111111'
    assert check(resource, 'ECR_CACHE_ROLE_ACCOUNT')[0]['verdict'] == expected


@pytest.mark.parametrize('region,account,expected', [('ap-northeast-1', '111111111111', 'PASS'),
    ('us-east-1', '111111111111', 'FAIL'), ('ap-northeast-1', '222222222222', 'FAIL')])
def test_kms_alias_arn_scope(region, account, expected):
    resource = target('alias', 'AWS::KMS::Alias', TargetKeyId=f'arn:aws:kms:{region}:{account}:key/id')
    resource.scope.account, resource.scope.region = '111111111111', 'ap-northeast-1'
    assert check(resource, 'KMS_ALIAS_TARGET_SCOPE')[0]['verdict'] == expected


def test_scope_linked_role_and_key_id():
    resource = target('stream', 'AWS::CloudWatch::MetricStream', RoleArn='role')
    role = target('role', 'AWS::IAM::Role')
    role.scope.account = '222222222222'
    resource.scope.account = '111111111111'
    data = linked_design(resource, [role], [('RoleArn', 'role')])
    result = next(r for r in run_resource_checks(data, resource) if r['rule_id'] == 'CLOUDWATCH_STREAM_ARN_ACCOUNT')
    assert result['verdict'] == 'NEEDS_REVIEW'  # Cross-scope relations are not resolved by the design resolver.
    role.scope = resource.scope.model_copy()
    result = next(r for r in run_resource_checks(data, resource) if r['rule_id'] == 'CLOUDWATCH_STREAM_ARN_ACCOUNT')
    assert result['verdict'] == 'PASS'
    resource = target('alias', 'AWS::KMS::Alias', TargetKeyId='key-id-only')
    assert check(resource, 'KMS_ALIAS_TARGET_SCOPE')[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('cidr,expected', [('10.0.0.0/8', 'PASS'), ('172.16.0.0/12', 'PASS'),
    ('192.168.1.1/32', 'PASS'), ('100.64.0.0/10', 'FAIL'), ('10.0.0.0/7', 'FAIL'),
    ('2001:db8::/64', 'FAIL'), ('bad', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
@pytest.mark.parametrize('kind', ['RemoteNodeNetworks', 'RemotePodNetworks'])
def test_eks_remote_cidr(kind, cidr, expected):
    resource = target('cluster', 'AWS::EKS::Cluster', RemoteNetworkConfig={kind: [{'Cidrs': [cidr]}]})
    assert check(resource, 'EKS_REMOTE_PRIVATE_CIDR')[0]['verdict'] == expected


@pytest.mark.parametrize('service,expected', [('10.1.0.0/16', 'FAIL'), ('172.20.0.0/16', 'PASS'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_eks_service_overlap(service, expected):
    resource = target('cluster', 'AWS::EKS::Cluster', KubernetesNetworkConfig={'ServiceIpv4Cidr': service},
        RemoteNetworkConfig={'RemoteNodeNetworks': [{'Cidrs': ['10.0.0.0/8']}]})
    assert check(resource, 'EKS_REMOTE_SERVICE_CIDR')[0]['verdict'] == expected


@pytest.mark.parametrize('family,cidrs,expected', [('ipv4', ['::/0'], 'FAIL'),
    ('ipv4', ['0.0.0.0/0'], 'PASS'), ('ipv6', ['::/0','0.0.0.0/0'], 'PASS'),
    (UNKNOWN, ['::/0'], 'NEEDS_REVIEW'), ('ipv4', [UNKNOWN], 'NEEDS_REVIEW')])
def test_eks_public_access_family(family, cidrs, expected):
    resource = target('cluster', 'AWS::EKS::Cluster', KubernetesNetworkConfig={'IpFamily':family},
        ResourcesVpcConfig={'PublicAccessCidrs':cidrs})
    assert check(resource, 'EKS_PUBLIC_CIDR_FAMILY')[0]['verdict'] == expected


@pytest.mark.parametrize('body,expected', [
    ({'widgets': []}, 'PASS'), ({}, 'FAIL'), ([], 'FAIL'),
    ({'widgets': [], 'variables': [{}]*26}, 'FAIL'),
    ({'widgets': [{'type':'text','properties':{'markdown':'x'}}]*500}, 'PASS'),
    ({'widgets': [{'type':'text','properties':{'markdown':'x'}}]*501}, 'FAIL'),
    ({'widgets': [], 'end':'2026-10-03T00:00:00Z'}, 'FAIL'),
    ({'widgets': [], 'periodOverride':'inherit'}, 'PASS'),
    ({'widgets': [{'type':'text','x':0,'properties':{}}]}, 'FAIL'),
    ({'widgets': [{'type':'text','x':23,'y':0,'width':24,'height':1000,'properties':{}}]}, 'PASS'),
    ({'widgets': [{'type':'text','x':24,'y':0,'properties':{}}]}, 'FAIL'),
])
def test_dashboard_structure(body, expected):
    resource = target('dashboard', 'AWS::CloudWatch::Dashboard', DashboardBody=json.dumps(body))
    assert check(resource, 'CLOUDWATCH_DASHBOARD_STRUCTURE')[0]['verdict'] == expected


@pytest.mark.parametrize('body,expected', [('bad json', 'FAIL'), ('{"widgets":[],"x":NaN}', 'FAIL'),
    (UNKNOWN, 'NEEDS_REVIEW'), ('{{resolve:ssm:body}}','NEEDS_REVIEW')])
def test_dashboard_unresolved_json(body, expected):
    resource = target('dashboard', 'AWS::CloudWatch::Dashboard', DashboardBody=body)
    assert check(resource, 'CLOUDWATCH_DASHBOARD_STRUCTURE')[0]['verdict'] == expected


@pytest.mark.parametrize('name,expected', [('Metric Name', 'PASS'), (' ', 'FAIL'),
    ('metric\nname', 'FAIL'), ('日本語', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_metric_filter_ascii(name, expected):
    resource = target('stream', 'AWS::CloudWatch::MetricStream', IncludeFilters=[{'MetricNames':[name]}])
    assert check(resource, 'CLOUDWATCH_STREAM_METRIC_NAMES')[0]['verdict'] == expected


@pytest.mark.parametrize('statistic,expected', [('p0','PASS'), ('p100','PASS'),('p99.99','PASS'),
    ('p100.1','FAIL'),('Average','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_otel_percentile(statistic, expected):
    resource = target('stream', 'AWS::CloudWatch::MetricStream', OutputFormat='opentelemetry1.0',
        StatisticsConfigurations=[{'AdditionalStatistics':[statistic]}])
    assert check(resource, 'CLOUDWATCH_STREAM_OTEL_PERCENTILES')[0]['verdict'] == expected
