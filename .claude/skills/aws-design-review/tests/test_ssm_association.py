import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('props,kind,expected', [
    ({}, 'Automation', 'FAIL'), ({'AutomationTargetParameterName': 'InstanceId'}, 'Automation', 'PASS'),
    ({'AutomationTargetParameterName': UNKNOWN}, 'Automation', 'NEEDS_REVIEW'),
    ({}, UNKNOWN, 'NEEDS_REVIEW'), ({}, 'Command', None),
])
def test_automation_rate_target(props, kind, expected):
    resource = target('association', 'AWS::SSM::Association', Name={'Ref': 'doc'},
        MaxConcurrency='10%', Targets=[{'Key': 'tag:name', 'Values': ['test']}], **props)
    document = target('doc', 'AWS::SSM::Document', DocumentType=kind)
    data = linked_design(resource, [document], [('Name', 'doc')])
    results = run_resource_checks(data, resource)
    assert (results[0]['verdict'] if results else None) == expected


def test_no_explicit_rate_control_is_not_inferred():
    resource = target('association', 'AWS::SSM::Association', Name='doc', Targets=[{}])
    assert run_resource_checks(linked_design(resource), resource) == []
