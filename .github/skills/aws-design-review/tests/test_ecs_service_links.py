import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(props, task_props, target_type=None):
    resource = target('service', 'AWS::ECS::Service', TaskDefinition={'Ref': 'task'}, **props)
    task = target('task', 'AWS::ECS::TaskDefinition', **task_props)
    targets, links = [task], [('TaskDefinition', 'task')]
    if target_type is not None:
        targets.append(target('group', 'AWS::ElasticLoadBalancingV2::TargetGroup', TargetType=target_type))
        links.append(('LoadBalancers/0/TargetGroupArn', 'group'))
    data = linked_design(resource, targets, links)
    return {r['rule_id']: r['verdict'] for r in run_resource_checks(data, resource)}


@pytest.mark.parametrize('volumes,expected', [
    ([{'Name':'data'}], 'PASS'), ([{'Name':'other'}], 'FAIL'), ([], 'FAIL'),
    (UNKNOWN, 'NEEDS_REVIEW'), ([{'Name':UNKNOWN}], 'NEEDS_REVIEW'),
    ([{'Name':'data'},{'Name':'data'}], 'NEEDS_REVIEW'),
    ([{'Name':'data'},{'Fn::If':['condition',{'Name':'other'},{'Ref':'AWS::NoValue'}]}], 'NEEDS_REVIEW'),
])
def test_service_volume_reference(volumes, expected):
    assert check({'VolumeConfigurations':[{'Name':'data'}]}, {'Volumes':volumes})['ECS_SERVICE_VOLUME_REFERENCE'] == expected


def test_service_volume_absent_and_unknown_configuration():
    assert check({'VolumeConfigurations':[{'Name':'data'}]}, {})['ECS_SERVICE_VOLUME_REFERENCE'] == 'FAIL'
    assert check({'VolumeConfigurations':UNKNOWN}, {})['ECS_SERVICE_VOLUME_REFERENCE'] == 'NEEDS_REVIEW'
    assert check({'VolumeConfigurations':[{'Name':UNKNOWN}]}, {'Volumes':[{'Name':'data'}]})['ECS_SERVICE_VOLUME_REFERENCE'] == 'NEEDS_REVIEW'


def test_service_volume_unlinked_task():
    resource = target('service', 'AWS::ECS::Service', TaskDefinition='external', VolumeConfigurations=[{'Name':'data'}])
    data = linked_design(resource, [], [])
    findings = {r['rule_id']:r['verdict'] for r in run_resource_checks(data, resource)}
    assert findings['ECS_SERVICE_VOLUME_REFERENCE'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('names,expected', [
    (['one','two'],'FAIL'), (['one','one'],None), (['one'],None),
    (['one',None],'NEEDS_REVIEW'),
])
def test_multiple_literal_target_groups_require_linked_role(names, expected):
    groups = [{'TargetGroupArn': f'arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:targetgroup/{name}/0123456789abcdef' if name else UNKNOWN} for name in names]
    assert check({'Role':'role','LoadBalancers':groups}, {'NetworkMode':'bridge'}).get('ECS_SERVICE_LINKED_ROLE_REQUIRED') == expected


@pytest.mark.parametrize('ids,expected', [(['a','b'],'FAIL'), (['a','a'],None)])
def test_multiple_linked_target_groups_require_linked_role(ids, expected):
    resource = target('service','AWS::ECS::Service',Role='role',LoadBalancers=[{'TargetGroupArn':{'Ref':id}} for id in ids])
    groups = [target(id,'AWS::ElasticLoadBalancingV2::TargetGroup') for id in sorted(set(ids))]
    data = linked_design(resource, groups, [(f'LoadBalancers/{i}/TargetGroupArn',id) for i,id in enumerate(ids)])
    findings = {r['rule_id']:r['verdict'] for r in run_resource_checks(data,resource)}
    assert findings.get('ECS_SERVICE_LINKED_ROLE_REQUIRED') == expected


def test_literal_and_linked_target_group_may_be_aliases():
    resource = target('service','AWS::ECS::Service',Role='role',LoadBalancers=[
        {'TargetGroupArn':{'Ref':'group'}},
        {'TargetGroupArn':'arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:targetgroup/one/0123456789abcdef'}])
    data = linked_design(resource,[target('group','AWS::ElasticLoadBalancingV2::TargetGroup')],[('LoadBalancers/0/TargetGroupArn','group')])
    findings = {r['rule_id']:r['verdict'] for r in run_resource_checks(data,resource)}
    assert findings['ECS_SERVICE_LINKED_ROLE_REQUIRED'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('mode,props,expected', [
    ('awsvpc', {}, 'FAIL'), ('awsvpc', {'NetworkConfiguration': {}}, 'PASS'),
    ('bridge', {}, 'PASS'), ('host', {'NetworkConfiguration': {}}, 'FAIL'),
    (UNKNOWN, {}, 'NEEDS_REVIEW'), ('awsvpc', {'NetworkConfiguration': UNKNOWN}, 'NEEDS_REVIEW'),
])
def test_network_mode(mode, props, expected):
    assert check(props, {'NetworkMode': mode})['ECS_SERVICE_TASK_NETWORK'] == expected


@pytest.mark.parametrize('mode,expected', [('awsvpc', 'FAIL'), ('bridge', 'PASS'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_role_network(mode, expected):
    assert check({'Role': 'role'}, {'NetworkMode': mode})['ECS_SERVICE_ROLE_NETWORK'] == expected


@pytest.mark.parametrize('runtime,task_count,expected', [(5,5,'PASS'),(6,5,'FAIL'),(0,None,'NEEDS_REVIEW')])
def test_constraint_total(runtime, task_count, expected):
    assert check({'PlacementConstraints': [{}] * runtime}, {'PlacementConstraints': UNKNOWN if task_count is None else [{}] * task_count})['ECS_SERVICE_COMBINED_CONSTRAINTS'] == expected


@pytest.mark.parametrize('name,port,mappings,expected', [
    ('app',80,[{'ContainerPort':80}],'PASS'), ('app',81,[{'ContainerPort':80}],'FAIL'),
    ('other',80,[{'ContainerPort':80}],'FAIL'), ('app',80,UNKNOWN,'NEEDS_REVIEW'),
    ('app',80,[{'ContainerPortRange':'80-90'}],'NEEDS_REVIEW'),
])
def test_container_port(name, port, mappings, expected):
    result = check({'LoadBalancers':[{'ContainerName':name,'ContainerPort':port}]},
        {'ContainerDefinitions':[{'Name':'app','PortMappings':mappings}]})
    assert result['ECS_SERVICE_CONTAINER_PORT'] == expected


@pytest.mark.parametrize('kind,expected', [('ip','PASS'),('instance','FAIL'),('lambda','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_awsvpc_target_type(kind, expected):
    result = check({'LoadBalancers':[{'TargetGroupArn':{'Ref':'group'}}]}, {'NetworkMode':'awsvpc'}, kind)
    assert result['ECS_SERVICE_AWSVPC_TARGET_TYPE'] == expected


def test_awsvpc_classic_lb_rejected():
    assert check({'LoadBalancers':[{'LoadBalancerName':'classic'}]}, {'NetworkMode':'awsvpc'})['ECS_SERVICE_AWSVPC_TARGET_TYPE'] == 'FAIL'


@pytest.mark.parametrize('expression', [{'Fn::If':['condition',{},{}]}, {'Ref':'config'}, {'Fn::Future':'input'}])
def test_intrinsic_network_config_is_not_treated_as_resolved(expression):
    assert check({'NetworkConfiguration':expression}, {'NetworkMode':'bridge'})['ECS_SERVICE_TASK_NETWORK'] == 'NEEDS_REVIEW'


def test_intrinsic_container_definition_does_not_become_absent_name():
    result = check({'LoadBalancers':[{'ContainerName':'app','ContainerPort':80}]},
        {'ContainerDefinitions':[{'Fn::If':['condition',{'Name':'app'}, {'Ref':'AWS::NoValue'}]}]})
    assert result['ECS_SERVICE_CONTAINER_PORT'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('options,secrets,expected', [
    ({'splunk-url':'https://example.invalid'},[{'Name':'splunk-token','ValueFrom':'secret'}],'PASS'),
    ({'splunk-url':'https://example.invalid'},[],'FAIL'),
    ({'splunk-url':'https://example.invalid'},UNKNOWN,'NEEDS_REVIEW'),
])
def test_service_connect_splunk_options(options, secrets, expected):
    result = check({'ServiceConnectConfiguration':{'LogConfiguration':{
        'LogDriver':'splunk','Options':options,'SecretOptions':secrets}}}, {})
    assert result['ECS_SERVICE_SPLUNK_OPTIONS'] == expected


@pytest.mark.parametrize('props,task_props', [
    ({'ServiceRegistries':[{'RegistryArn':'arn'}]}, {}),
    ({'DeploymentController':{'Type':'EXTERNAL'}}, {}),
    ({}, {'InferenceAccelerators':[{'DeviceName':'accel'}]}),
])
def test_explicit_role_with_service_linked_role_requirement(props, task_props):
    assert check({'Role':'role',**props},task_props)['ECS_SERVICE_LINKED_ROLE_REQUIRED'] == 'FAIL'


def test_conditional_registry_does_not_prove_service_discovery():
    result = check({'Role':'role','ServiceRegistries':[{'Fn::If':['condition',{'RegistryArn':'arn'},{'Ref':'AWS::NoValue'}]}]}, {})
    assert 'ECS_SERVICE_LINKED_ROLE_REQUIRED' not in result


@pytest.mark.parametrize('mapping,expected_reference,expected_timeout', [
    ({'Name':'web','AppProtocol':'http'},'PASS','PASS'),
    ({'Name':'web','AppProtocol':'http2'},'PASS','PASS'),
    ({'Name':'web','AppProtocol':'grpc'},'PASS','PASS'),
    ({'Name':'web'},'PASS','FAIL'), ({'Name':'web','AppProtocol':UNKNOWN},'PASS','NEEDS_REVIEW'),
    ({'Name':'other'},'FAIL','NEEDS_REVIEW'), ({'Name':UNKNOWN},'NEEDS_REVIEW','NEEDS_REVIEW'),
])
def test_service_connect_named_port_and_timeout(mapping, expected_reference, expected_timeout):
    props = {'ServiceConnectConfiguration':{'Enabled':True,'Services':[{'PortName':'web','Timeout':{'PerRequestTimeoutSeconds':0}}]}}
    result = check(props, {'ContainerDefinitions':[{'PortMappings':[mapping]}]})
    assert result['ECS_SERVICE_CONNECT_PORT_REFERENCE'] == expected_reference
    assert result['ECS_SERVICE_CONNECT_REQUEST_TIMEOUT'] == expected_timeout


def test_service_connect_duplicate_port_names_and_disabled_configuration():
    config = {'Enabled':True,'Services':[{'PortName':'web'}]}
    task = {'ContainerDefinitions':[{'PortMappings':[{'Name':'web'},{'Name':'web'}]}]}
    assert check({'ServiceConnectConfiguration':config}, task)['ECS_SERVICE_CONNECT_PORT_REFERENCE'] == 'NEEDS_REVIEW'
    config['Enabled'] = False
    assert 'ECS_SERVICE_CONNECT_PORT_REFERENCE' not in check({'ServiceConnectConfiguration':config}, task)


@pytest.mark.parametrize('providers,expected', [
    (['FARGATE'],'FAIL'), (['FARGATE_SPOT'],'FAIL'), (['FARGATE','FARGATE_SPOT'],'FAIL'),
    (['FARGATE','custom'],'NEEDS_REVIEW'), ([UNKNOWN],'NEEDS_REVIEW'),
])
@pytest.mark.parametrize('props', [
    {'SchedulingStrategy':'DAEMON'}, {'PlacementConstraints':[{'Type':'distinctInstance'}]},
    {'VolumeConfigurations':[{'ManagedEBSVolume':{'VolumeType':'standard'}}]},
])
def test_fargate_capacity_provider_conditions(providers, expected, props):
    props = {**props, 'CapacityProviderStrategy':[{'CapacityProvider':p,'Weight':1} for p in providers]}
    assert check(props,{})['ECS_SERVICE_FARGATE_CAPACITY'] == expected


def test_empty_strategy_does_not_identify_cluster_default():
    assert 'ECS_SERVICE_FARGATE_CAPACITY' not in check({'CapacityProviderStrategy':[],'SchedulingStrategy':'DAEMON'}, {})
