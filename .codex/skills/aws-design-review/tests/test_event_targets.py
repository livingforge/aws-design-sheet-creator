import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_autoscaling_group_nested_constraints import design


def check(kind, **props):
    resource = target('main', kind, **props)
    resource.scope.account = '111111111111'
    return {r['rule_id']: r['verdict'] for r in run_resource_checks(design(resource), resource)}


@pytest.mark.parametrize('field', ['Input', 'InputPath', 'InputTransformer'])
@pytest.mark.parametrize('account,expected', [('111111111111', 'PASS'), ('222222222222', 'FAIL')])
def test_bus_target_account(field, account, expected):
    entry = {'Arn': f'arn:aws:events:us-east-1:{account}:event-bus/bus', field: '{}' if field != 'InputTransformer' else {}}
    assert check('AWS::Events::Rule', Targets=[entry])['EVENTS_CROSS_ACCOUNT_BUS_INPUT'] == expected


def test_unknown_arn_or_input_and_non_bus():
    assert check('AWS::Events::Rule', Targets=[{'Arn': UNKNOWN, 'Input': '{}'}])['EVENTS_CROSS_ACCOUNT_BUS_INPUT'] == 'NEEDS_REVIEW'
    assert check('AWS::Events::Rule', Targets=[{'Arn': 'arn:aws:events:us-east-1:222222222222:event-bus/bus', 'Input': UNKNOWN}])['EVENTS_CROSS_ACCOUNT_BUS_INPUT'] == 'NEEDS_REVIEW'
    assert 'EVENTS_CROSS_ACCOUNT_BUS_INPUT' not in check('AWS::Events::Rule', Targets=[{'Arn': 'arn:aws:lambda:us-east-1:222222222222:function:fn', 'Input': '{}'}])


@pytest.mark.parametrize('entries,expected', [
    ([{}, {}], 'PASS'), ([{'Base': 1}, {}], 'PASS'), ([{'Base': 0}, {'Base': 0}], 'FAIL'),
    ([{'Base': 1}, {'Base': 2}], 'FAIL'), ([{'Base': UNKNOWN}, {}], 'NEEDS_REVIEW'),
    (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_capacity_provider_base_count(entries, expected):
    result = check('AWS::Events::Rule', Targets=[{'EcsParameters': {'CapacityProviderStrategy': entries}}])
    assert result['EVENTS_CAPACITY_PROVIDER_BASE_COUNT'] == expected


@pytest.mark.parametrize('other', ['LBCookieStickinessPolicy', 'Policies'])
def test_policy_names_cross_collections(other):
    props = {'AppCookieStickinessPolicy': [{'PolicyName': 'sticky'}], other: [{'PolicyName': 'sticky'}]}
    assert check('AWS::ElasticLoadBalancing::LoadBalancer', **props)['CLASSIC_ELB_POLICY_NAMES'] == 'FAIL'
    props[other] = [{'PolicyName': 'different'}]
    assert check('AWS::ElasticLoadBalancing::LoadBalancer', **props)['CLASSIC_ELB_POLICY_NAMES'] == 'PASS'
    props[other] = UNKNOWN
    assert check('AWS::ElasticLoadBalancing::LoadBalancer', **props)['CLASSIC_ELB_POLICY_NAMES'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('compat,mode,expected', [
    (['FARGATE'], 'awsvpc', 'PASS'), (['EC2'], 'awsvpc', 'FAIL'),
    (['FARGATE'], 'bridge', 'FAIL'), (UNKNOWN, 'awsvpc', 'NEEDS_REVIEW'),
    (['FARGATE'], UNKNOWN, 'NEEDS_REVIEW'),
])
def test_linked_task_compatibility(compat, mode, expected):
    resource = target('rule', 'AWS::Events::Rule', Targets=[{'EcsParameters': {
        'LaunchType': 'FARGATE', 'TaskDefinitionArn': {'Ref': 'task'}, 'NetworkConfiguration': {}}}])
    task = target('task', 'AWS::ECS::TaskDefinition', RequiresCompatibilities=compat, NetworkMode=mode)
    data = linked_design(resource, [task], [('Targets/0/EcsParameters/TaskDefinitionArn', 'task')])
    result = {r['rule_id']: r['verdict'] for r in run_resource_checks(data, resource)}
    assert result['EVENTS_ECS_TASK_COMPATIBILITY'] == expected


@pytest.mark.parametrize('second,expected', [('vpc-aa', 'PASS'), ('vpc-bb', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_event_network_membership(second, expected):
    resource = target('rule', 'AWS::Events::Rule', Targets=[{'EcsParameters': {'NetworkConfiguration': {
        'AwsVpcConfiguration': {'Subnets': ['subnet-a'], 'SecurityGroups': ['sg-a']}}}}])
    subnet = target('subnet', 'AWS::EC2::Subnet', VpcId='vpc-aa')
    sg = target('sg', 'AWS::EC2::SecurityGroup', VpcId=second)
    base = 'Targets/0/EcsParameters/NetworkConfiguration/AwsVpcConfiguration/'
    data = linked_design(resource, [subnet, sg], [(base + 'Subnets/0', 'subnet'), (base + 'SecurityGroups/0', 'sg')])
    result = {r['rule_id']: r['verdict'] for r in run_resource_checks(data, resource)}
    assert result['EVENTS_ECS_VPC_MEMBERSHIP'] == expected


@pytest.mark.parametrize('zone,expected', [('ap-northeast-1a', 'FAIL'), ('ap-northeast-1c', 'PASS'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_classic_subnet_zones(zone, expected):
    resource = target('lb', 'AWS::ElasticLoadBalancing::LoadBalancer', Subnets=['a', 'b'])
    a = target('a', 'AWS::EC2::Subnet', AvailabilityZone='ap-northeast-1a')
    b = target('b', 'AWS::EC2::Subnet', AvailabilityZone=zone)
    data = linked_design(resource, [a, b], [('Subnets/0', 'a'), ('Subnets/1', 'b')])
    result = {r['rule_id']: r['verdict'] for r in run_resource_checks(data, resource)}
    assert result['CLASSIC_ELB_SUBNET_ZONES'] == expected


@pytest.mark.parametrize('props,expected', [({}, 'PASS'), ({'EventSourceName': 'aws.partner/vendor/source'}, 'FAIL'),
    ({'EventSourceName': UNKNOWN}, 'NEEDS_REVIEW')])
def test_linked_partner_bus_state(props, expected):
    resource = target('rule', 'AWS::Events::Rule', EventBusName={'Ref': 'bus'}, State='ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS')
    bus = target('bus', 'AWS::Events::EventBus', **props)
    data = linked_design(resource, [bus], [('EventBusName', 'bus')])
    results = {r['rule_id']: r['verdict'] for r in run_resource_checks(data, resource)}
    assert results['EVENTS_PARTNER_BUS_MANAGEMENT_EVENTS'] == expected


@pytest.mark.parametrize('dedup,expected', [(True, 'PASS'), (False, 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_linked_fifo_queue_deduplication(dedup, expected):
    resource = target('rule', 'AWS::Events::Rule', Targets=[{'Arn': {'Ref': 'queue'}}])
    queue = target('queue', 'AWS::SQS::Queue', FifoQueue=True, ContentBasedDeduplication=dedup)
    data = linked_design(resource, [queue], [('Targets/0/Arn', 'queue')])
    results = {r['rule_id']: r['verdict'] for r in run_resource_checks(data, resource)}
    assert results['EVENTS_FIFO_TARGET_DEDUPLICATION'] == expected


@pytest.mark.parametrize('runtime,task_count,expected', [
    (5, 5, 'PASS'), (6, 5, 'FAIL'), (0, 10, 'PASS'),
    (0, 11, 'FAIL'), (1, None, 'NEEDS_REVIEW'), (11, None, 'FAIL'),
])
def test_combined_placement_constraints(runtime, task_count, expected):
    resource = target('rule', 'AWS::Events::Rule', Targets=[{'EcsParameters': {
        'TaskDefinitionArn': {'Ref': 'task'}, 'PlacementConstraints': [{} for _ in range(runtime)]}}])
    task = target('task', 'AWS::ECS::TaskDefinition',
        PlacementConstraints=UNKNOWN if task_count is None else [{} for _ in range(task_count)])
    data = linked_design(resource, [task], [('Targets/0/EcsParameters/TaskDefinitionArn', 'task')])
    results = {r['rule_id']: r['verdict'] for r in run_resource_checks(data, resource)}
    assert results['EVENTS_ECS_COMBINED_CONSTRAINTS'] == expected


def test_combined_constraints_missing_task_requires_review():
    results = check('AWS::Events::Rule', Targets=[{'EcsParameters': {'TaskDefinitionArn': 'external'}}])
    assert results['EVENTS_ECS_COMBINED_CONSTRAINTS'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('mapping,expected', [
    ({f'key{i}': '$.detail' for i in range(100)}, 'PASS'),
    ({f'key{i}': '$.detail' for i in range(101)}, 'FAIL'),
    ({'AWS.private': '$.detail'}, 'FAIL'), ({'aws.private': '$.detail'}, 'PASS'),
    ({'key': UNKNOWN}, 'PASS'), (UNKNOWN, 'NEEDS_REVIEW'),
    ({'Fn::If': ['condition', {}, {}]}, 'NEEDS_REVIEW'),
])
def test_input_path_map_size_and_reserved_keys(mapping, expected):
    results = check('AWS::Events::Rule', Targets=[{'InputTransformer': {'InputPathsMap': mapping}}])
    assert results['EVENTS_INPUT_PATHS_MAP'] == expected
