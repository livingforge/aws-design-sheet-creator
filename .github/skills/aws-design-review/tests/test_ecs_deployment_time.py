import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(configuration):
    resource = target('service', 'AWS::ECS::Service', DeploymentConfiguration=configuration)
    return {r['rule_id']: r['verdict'] for r in run_resource_checks(linked_design(resource), resource)}


@pytest.mark.parametrize('bake,canary,expected', [(1440,540,'PASS'),(1440,541,'FAIL'),(0,0,'PASS'),(UNKNOWN,10,'NEEDS_REVIEW')])
def test_canary_time_boundary(bake, canary, expected):
    result = check({'Strategy':'CANARY','BakeTimeInMinutes':bake,'CanaryConfiguration':{'CanaryBakeTimeInMinutes':canary}})
    assert result['ECS_SERVICE_DEPLOYMENT_TIME'] == expected


@pytest.mark.parametrize('percent,bake,wait,expected', [
    (50,1440,540,'PASS'), (50,1440,541,'FAIL'),
    (100,1440,1440,'PASS'), (11,0,220,'PASS'), (11,0,221,'FAIL'),
    (3,0,60,'PASS'), (3,1,60,'FAIL'),
    (33.3,0,660,'PASS'), (33.3,0,661,'FAIL'),
    (0,0,1,'NEEDS_REVIEW'), (True,0,1,'NEEDS_REVIEW'),
    (3.01,0,1,'NEEDS_REVIEW'), (UNKNOWN,0,1,'NEEDS_REVIEW'),
    (10,0,UNKNOWN,'NEEDS_REVIEW'),
])
def test_linear_steps_exclude_final_shift(percent, bake, wait, expected):
    result = check({'Strategy':'LINEAR','BakeTimeInMinutes':bake,
        'LinearConfiguration':{'StepPercent':percent,'StepBakeTimeInMinutes':wait}})
    assert result['ECS_SERVICE_DEPLOYMENT_TIME'] == expected


@pytest.mark.parametrize('strategy', ['CANARY','LINEAR'])
def test_documented_defaults(strategy):
    assert check({'Strategy':strategy})['ECS_SERVICE_DEPLOYMENT_TIME'] == 'PASS'


def test_unknown_configuration_does_not_use_defaults():
    assert check({'Strategy':'LINEAR','LinearConfiguration':{'Fn::If':['c',{},{}]}})['ECS_SERVICE_DEPLOYMENT_TIME'] == 'NEEDS_REVIEW'


def test_other_strategy_is_not_evaluated():
    assert 'ECS_SERVICE_DEPLOYMENT_TIME' not in check({'Strategy':'BLUE_GREEN'})
