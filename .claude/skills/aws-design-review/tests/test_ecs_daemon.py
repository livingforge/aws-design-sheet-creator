import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(containers, **properties):
    resource = target('daemon', 'AWS::ECS::DaemonTaskDefinition', ContainerDefinitions=containers, **properties)
    return run_resource_checks(linked_design(resource), resource)


@pytest.mark.parametrize('condition,other,expected', [
    ('START', {}, 'PASS'), ('COMPLETE', {'Essential': False}, 'PASS'),
    ('SUCCESS', {'Essential': True}, 'FAIL'), ('COMPLETE', {}, 'NEEDS_REVIEW'),
    ('SUCCESS', {'Essential': UNKNOWN}, 'NEEDS_REVIEW'),
    ('HEALTHY', {}, 'FAIL'), ('HEALTHY', {'HealthCheck': {'Command': ['CMD', 'true']}}, 'PASS'),
    ('HEALTHY', {'HealthCheck': UNKNOWN}, 'NEEDS_REVIEW'), ('future', {}, 'NEEDS_REVIEW')])
def test_dependency(condition, other, expected):
    results = check([{'Name': 'app', 'DependsOn': [{'ContainerName': 'init', 'Condition': condition}]},
                     {'Name': 'init', **other}])
    assert next(f['verdict'] for f in results if f['rule_id'] == 'ECS_DAEMON_DEPENDENCY_TARGET') == expected
    assert not any(f['rule_id'].startswith('ECS_TASK_') for f in results)


@pytest.mark.parametrize('others,expected', [([], 'FAIL'), ([{'Name': UNKNOWN}], 'NEEDS_REVIEW'),
    ([{'Name': 'init'}, {'Name': 'init'}], 'NEEDS_REVIEW')])
def test_ambiguous_or_absent_target(others, expected):
    result = check([{'Name': 'app', 'DependsOn': [{'ContainerName': 'init', 'Condition': 'START'}]}, *others])
    assert next(f['verdict'] for f in result if f['rule_id'] == 'ECS_DAEMON_DEPENDENCY_TARGET') == expected


@pytest.mark.parametrize('volumes,name,expected', [
    ([{'Name': 'data'}], 'data', 'PASS'), ([], 'data', 'FAIL'),
    ([{'Name': 'other'}], 'data', 'FAIL'), ([{'Name': UNKNOWN}], 'data', 'NEEDS_REVIEW'),
    (UNKNOWN, 'data', 'NEEDS_REVIEW'), ([{'Name': 'data'}], UNKNOWN, 'NEEDS_REVIEW')])
def test_mount(volumes, name, expected):
    result = check([{'Name': 'app', 'MountPoints': [{'SourceVolume': name}]}], Volumes=volumes)
    assert next(f['verdict'] for f in result if f['rule_id'] == 'ECS_DAEMON_MOUNT_VOLUME') == expected


def test_unresolved_containers_and_absent_volumes():
    assert all(f['verdict'] == 'NEEDS_REVIEW' for f in check(UNKNOWN))
    result = check([{'Name': 'app', 'MountPoints': [{'SourceVolume': 'data'}]}])
    assert next(f['verdict'] for f in result if f['rule_id'] == 'ECS_DAEMON_MOUNT_VOLUME') == 'FAIL'


@pytest.mark.parametrize('options,secrets,expected', [
    ({'awslogs-region': 'us-east-1', 'awslogs-group': 'logs'}, None, 'PASS'),
    ({'awslogs-region': 'us-east-1'}, None, 'FAIL'), ({}, [], 'FAIL'),
    (UNKNOWN, None, 'NEEDS_REVIEW'),
    ({'awslogs-region': 'us-east-1'}, [{'Name': 'awslogs-group', 'ValueFrom': 'secret'}], 'NEEDS_REVIEW'),
    ({}, UNKNOWN, 'NEEDS_REVIEW'),
    ({'awslogs-region': UNKNOWN, 'awslogs-group': 'logs'}, None, 'NEEDS_REVIEW')])
def test_awslogs_options(options, secrets, expected):
    config = {'LogDriver': 'awslogs', 'Options': options}
    if secrets is not None:
        config['SecretOptions'] = secrets
    result = check([{'Name': 'app', 'LogConfiguration': config}])
    assert next(f['verdict'] for f in result if f['rule_id'] == 'ECS_DAEMON_AWSLOGS_OPTIONS') == expected
