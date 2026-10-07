import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def verdict(resource, targets=(), links=()):
    return {f['rule_id']: f['verdict'] for f in run_resource_checks(linked_design(resource, targets, links), resource)}


@pytest.mark.parametrize('names,expected', [(['FARGATE'],'PASS'),
    (['FARGATE','FARGATE_SPOT'],'PASS'), (['custom'],'NEEDS_REVIEW'),
    (['FARGATE','custom'],'NEEDS_REVIEW'), ([UNKNOWN],'NEEDS_REVIEW'), ([], 'NEEDS_REVIEW')])
def test_builtin_strategy(names, expected):
    resource = target('set','AWS::ECS::TaskSet',PlatformVersion='1.4.0',
        CapacityProviderStrategy=[{'CapacityProvider': n} for n in names])
    assert verdict(resource)['ECS_TASKSET_PLATFORM_CAPACITY'] == expected


@pytest.mark.parametrize('config,expected', [({'AutoScalingGroupProvider': {'AutoScalingGroupArn': 'group'}}, 'FAIL'),
    ({'AutoScalingGroupProvider': UNKNOWN}, 'NEEDS_REVIEW'),
    ({'ManagedInstancesProvider': {}}, 'NEEDS_REVIEW'),
    ({'AutoScalingGroupProvider': {}, 'ManagedInstancesProvider': {}}, 'NEEDS_REVIEW')])
def test_linked_provider(config, expected):
    resource = target('set','AWS::ECS::TaskSet',PlatformVersion='LATEST',
        CapacityProviderStrategy=[{'CapacityProvider': {'Ref': 'provider'}}])
    provider = target('provider','AWS::ECS::CapacityProvider',**config)
    links = [('CapacityProviderStrategy/0/CapacityProvider','provider')]
    assert verdict(resource,[provider],links)['ECS_TASKSET_PLATFORM_CAPACITY'] == expected
    provider.scope.region = 'us-west-2'
    assert verdict(resource,[provider],links)['ECS_TASKSET_PLATFORM_CAPACITY'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('props', [{}, {'PlatformVersion':'LATEST','LaunchType':'FARGATE'}])
def test_inapplicable_platform(props):
    assert 'ECS_TASKSET_PLATFORM_CAPACITY' not in verdict(target('set','AWS::ECS::TaskSet',**props))


@pytest.mark.parametrize('controller,expected', [('EXTERNAL','PASS'), ('ECS','FAIL'),
    ('CODE_DEPLOY','FAIL'), (UNKNOWN,'NEEDS_REVIEW')])
def test_service_controller(controller, expected):
    resource = target('set','AWS::ECS::TaskSet',Service={'Ref':'service'})
    service = target('service','AWS::ECS::Service',DeploymentController={'Type':controller})
    assert verdict(resource,[service],[('Service','service')])['ECS_TASKSET_EXTERNAL_CONTROLLER'] == expected
