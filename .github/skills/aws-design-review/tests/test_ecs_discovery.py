import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(mode, config, record_type='SRV'):
    resource = target('service','AWS::ECS::Service', TaskDefinition={'Ref':'task'}, ServiceRegistries=[{'RegistryArn':{'Ref':'registry'},**config}])
    task = target('task','AWS::ECS::TaskDefinition', NetworkMode=mode, ContainerDefinitions=[{'Name':'app','PortMappings':[{'ContainerPort':80}]}])
    registry = target('registry','AWS::ServiceDiscovery::Service',DnsConfig={'DnsRecords':[{'Type':record_type}]})
    data = linked_design(resource,[task,registry],[('TaskDefinition','task'),('ServiceRegistries/0/RegistryArn','registry')])
    return {r['rule_id']:r['verdict'] for r in run_resource_checks(data,resource)}


@pytest.mark.parametrize('mode,props,expected', [
    ('bridge',{},'FAIL'),('host',{'ContainerName':'app','ContainerPort':80},'PASS'),
    ('bridge',{'ContainerName':'app'},'FAIL'),('bridge',{'ContainerName':UNKNOWN,'ContainerPort':80},'NEEDS_REVIEW'),
    ('awsvpc',{},'FAIL'),('awsvpc',{'Port':80},'PASS'),
    ('awsvpc',{'ContainerName':'app','ContainerPort':80},'PASS'),
    ('awsvpc',{'ContainerName':'app','ContainerPort':80,'Port':80},'FAIL'),
    ('awsvpc',{'Port':UNKNOWN},'NEEDS_REVIEW'),
    (UNKNOWN,{'Port':80},'NEEDS_REVIEW'),
])
def test_registry_conditions(mode, props, expected):
    assert check(mode,props)['ECS_SERVICE_REGISTRY_CONFIGURATION']==expected


def test_registry_named_port_must_match_task():
    assert check('bridge',{'ContainerName':'app','ContainerPort':81})['ECS_SERVICE_REGISTRY_CONTAINER_PORT']=='FAIL'


def test_unknown_dns_type_and_non_srv_records():
    assert check('awsvpc',{},UNKNOWN)['ECS_SERVICE_REGISTRY_CONFIGURATION']=='NEEDS_REVIEW'
    assert 'ECS_SERVICE_REGISTRY_CONFIGURATION' not in check('awsvpc',{},'A')
