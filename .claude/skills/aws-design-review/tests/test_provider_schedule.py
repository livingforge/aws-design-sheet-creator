"""Declared prerequisites, missing evidence and explicit-reference boundaries."""
import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def findings(resource, targets=(), links=()):
    return {f['rule_id']: f['verdict'] for f in
            run_resource_checks(linked_design(resource, targets, links), resource)}


@pytest.mark.parametrize('controller,expected', [
    ('EXTERNAL', 'PASS'), ('ECS', 'FAIL'), ('CODE_DEPLOY', 'FAIL'),
    ('FUTURE', 'NEEDS_REVIEW'), (UNKNOWN, 'NEEDS_REVIEW'), (None, 'NEEDS_REVIEW')])
def test_primary_controller(controller, expected):
    primary = target('primary', 'AWS::ECS::PrimaryTaskSet', Service={'Ref': 'service'})
    service = target('service', 'AWS::ECS::Service', **(
        {'DeploymentController': {'Type': controller}} if controller is not None else {}))
    assert findings(primary, [service], [('Service', 'service')])['ECS_PRIMARY_EXTERNAL_CONTROLLER'] == expected


@pytest.mark.parametrize('mode', ['unlinked', 'conditional', 'cross-region', 'wrong-type'])
def test_primary_does_not_infer_reference(mode):
    primary = target('primary', 'AWS::ECS::PrimaryTaskSet', Service='service')
    service = target('service', 'AWS::ECS::Service', DeploymentController={'Type': 'EXTERNAL'})
    data = linked_design(primary, [service], [] if mode == 'unlinked' else [('Service', 'service')])
    if mode == 'conditional':
        data.relations[0].condition = 'UseService'
    elif mode == 'cross-region':
        service.scope.region = 'us-west-2'
    elif mode == 'wrong-type':
        service.type = 'AWS::ECS::Cluster'
    assert next(f for f in run_resource_checks(data, primary)
                if f['rule_id'] == 'ECS_PRIMARY_EXTERNAL_CONTROLLER')['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('flag,expected', [(True, 'PASS'), (False, 'FAIL'),
    (UNKNOWN, 'NEEDS_REVIEW'), (None, 'NEEDS_REVIEW'), ('true', 'NEEDS_REVIEW')])
def test_provider_group_protection(flag, expected):
    provider = target('provider', 'AWS::ECS::CapacityProvider', AutoScalingGroupProvider={
        'ManagedTerminationProtection': 'ENABLED', 'AutoScalingGroupArn': {'Ref': 'group'}})
    group = target('group', 'AWS::AutoScaling::AutoScalingGroup', **(
        {'NewInstancesProtectedFromScaleIn': flag} if flag is not None else {}))
    assert findings(provider, [group], [('AutoScalingGroupProvider/AutoScalingGroupArn', 'group')])[
        'ECS_PROVIDER_ASG_PROTECTION'] == expected


@pytest.mark.parametrize('flag', ['DISABLED', None, UNKNOWN])
def test_provider_protection_activation(flag):
    provider = target('provider', 'AWS::ECS::CapacityProvider', AutoScalingGroupProvider=(
        {'ManagedTerminationProtection': flag} if flag is not None else {}))
    result = findings(provider)
    if flag == UNKNOWN:
        assert result['ECS_PROVIDER_ASG_PROTECTION'] == 'NEEDS_REVIEW'
    else:
        assert 'ECS_PROVIDER_ASG_PROTECTION' not in result


@pytest.mark.parametrize('vpcs,expected', [(['vpc-a', 'vpc-a'], 'PASS'),
    (['vpc-a', 'vpc-b'], 'FAIL'), (['vpc-a', UNKNOWN], 'NEEDS_REVIEW')])
def test_provider_subnet_vpc(vpcs, expected):
    base = 'ManagedInstancesProvider/InstanceLaunchTemplate/NetworkConfiguration'
    provider = target('provider', 'AWS::ECS::CapacityProvider', ManagedInstancesProvider={
        'InstanceLaunchTemplate': {'NetworkConfiguration': {'Subnets': ['one', 'two'], 'SecurityGroups': UNKNOWN}}})
    subnets = [target(name, 'AWS::EC2::Subnet', VpcId=vpc) for name, vpc in zip(['one', 'two'], vpcs)]
    links = [(base + '/Subnets/' + str(i), subnet.id) for i, subnet in enumerate(subnets)]
    assert findings(provider, subnets, links)['ECS_PROVIDER_SUBNET_VPC'] == expected
    assert findings(provider, subnets)['ECS_PROVIDER_SUBNET_VPC'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('schedule,expected', [
    ('cron(0 12 * * ? *)', 'PASS'), ('rate(1 day)', 'FAIL'),
    ('at(2026-12-01T00:00:00)', 'FAIL'), (None, 'FAIL'),
    (UNKNOWN, 'NEEDS_REVIEW'), ('cron(${Schedule})', 'NEEDS_REVIEW'), ('bad', 'NEEDS_REVIEW')])
def test_window_offset(schedule, expected):
    window = target('window', 'AWS::SSM::MaintenanceWindow', ScheduleOffset=2,
                    **({'Schedule': schedule} if schedule is not None else {}))
    assert findings(window)['SSM_WINDOW_OFFSET_CRON'] == expected


@pytest.mark.parametrize('offset', [UNKNOWN, -1, True, '2'])
def test_window_offset_unknown_or_invalid(offset):
    window = target('window', 'AWS::SSM::MaintenanceWindow', ScheduleOffset=offset, Schedule='rate(1 day)')
    assert findings(window)['SSM_WINDOW_OFFSET_CRON'] == 'NEEDS_REVIEW'


def test_window_without_offset():
    window = target('window', 'AWS::SSM::MaintenanceWindow', Schedule='rate(1 day)')
    assert 'SSM_WINDOW_OFFSET_CRON' not in findings(window)
