import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('properties,expected', [
    ({}, 'PASS'), ({'LogGroupClass': 'STANDARD'}, 'PASS'),
    ({'LogGroupClass': 'INFREQUENT_ACCESS'}, 'FAIL'),
    ({'LogGroupClass': 'DELIVERY'}, 'FAIL'),
    ({'LogGroupClass': UNKNOWN}, 'NEEDS_REVIEW'),
    ({'LogGroupClass': 'FUTURE_CLASS'}, 'NEEDS_REVIEW'),
])
def test_linked_class(properties, expected):
    resource = target('transformer', 'AWS::Logs::Transformer', LogGroupIdentifier={'Ref': 'group'})
    group = target('group', 'AWS::Logs::LogGroup', **properties)
    design = linked_design(resource, [group], [('LogGroupIdentifier', 'group')])
    assert run_resource_checks(design, resource)[0]['verdict'] == expected


@pytest.mark.parametrize('identifier', ['my-group', UNKNOWN, {'Ref': 'missing'}])
def test_unresolved_group(identifier):
    resource = target('transformer', 'AWS::Logs::Transformer', LogGroupIdentifier=identifier)
    assert run_resource_checks(linked_design(resource), resource)[0]['verdict'] == 'NEEDS_REVIEW'


def test_cross_region_group_is_not_resolved():
    resource = target('transformer', 'AWS::Logs::Transformer', LogGroupIdentifier={'Ref': 'group'})
    group = target('group', 'AWS::Logs::LogGroup', LogGroupClass='INFREQUENT_ACCESS')
    group.scope.region = 'us-west-2'
    design = linked_design(resource, [group], [('LogGroupIdentifier', 'group')])
    assert run_resource_checks(design, resource)[0]['verdict'] == 'NEEDS_REVIEW'
