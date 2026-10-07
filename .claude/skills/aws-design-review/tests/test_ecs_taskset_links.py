import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(mode='awsvpc', kind='ip', port=80, registry=None, linked_task=True, cross_region=False):
    props = {'TaskDefinition':{'Ref':'task'}, 'LoadBalancers':[{'TargetGroupArn':{'Ref':'group'},'ContainerName':'app','ContainerPort':port}]}
    if registry is not None:
        props['ServiceRegistries'] = [{'RegistryArn':{'Ref':'registry'}, **registry}]
    resource = target('set','AWS::ECS::TaskSet', **props)
    task = target('task','AWS::ECS::TaskDefinition', NetworkMode=mode, ContainerDefinitions=[{'Name':'app','PortMappings':[{'ContainerPort':80}]}])
    group = target('group','AWS::ElasticLoadBalancingV2::TargetGroup', TargetType=kind)
    if cross_region:
        group.scope.region = 'us-west-2'
    service = target('registry','AWS::ServiceDiscovery::Service',DnsConfig={'DnsRecords':[{'Type':'SRV'}]})
    links = [('LoadBalancers/0/TargetGroupArn','group'),('ServiceRegistries/0/RegistryArn','registry')]
    if linked_task:
        links.append(('TaskDefinition','task'))
    data = linked_design(resource,[task,group,service],links)
    return {r['rule_id']:r['verdict'] for r in run_resource_checks(data,resource)}


@pytest.mark.parametrize('mode,kind,expected', [
    ('awsvpc','ip','PASS'), ('awsvpc','instance','FAIL'), ('awsvpc','lambda','FAIL'),
    ('awsvpc',UNKNOWN,'NEEDS_REVIEW'), (UNKNOWN,'ip','NEEDS_REVIEW'), ('bridge','instance',None),
])
def test_target_type(mode,kind,expected):
    assert check(mode,kind).get('ECS_TASKSET_AWSVPC_TARGET_TYPE') == expected


def test_port_match_and_unresolved_references():
    assert check()['ECS_TASKSET_CONTAINER_PORT'] == 'PASS'
    assert check(port=81)['ECS_TASKSET_CONTAINER_PORT'] == 'FAIL'
    assert check(linked_task=False)['ECS_TASKSET_CONTAINER_PORT'] == 'NEEDS_REVIEW'
    assert check(cross_region=True)['ECS_TASKSET_AWSVPC_TARGET_TYPE'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('mode,registry,expected', [
    ('bridge',{},'FAIL'), ('bridge',{'ContainerName':'app','ContainerPort':80},'PASS'),
    ('awsvpc',{'Port':80},'PASS'),
    ('awsvpc',{'ContainerName':'app','ContainerPort':80,'Port':80},'FAIL'),
    ('awsvpc',{'Port':UNKNOWN},'NEEDS_REVIEW'),
])
def test_taskset_registry(mode,registry,expected):
    assert check(mode,registry=registry)['ECS_TASKSET_REGISTRY_CONFIGURATION'] == expected


def test_registry_port_matches_task_definition():
    assert check('bridge',registry={'ContainerName':'app','ContainerPort':81})['ECS_TASKSET_REGISTRY_CONTAINER_PORT'] == 'FAIL'
