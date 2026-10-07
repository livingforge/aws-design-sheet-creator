import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('text,expected', [
    ('日本語 Å １２_.:/=+-@', 'PASS'), ('', 'PASS'), ('a\u00a0b', 'PASS'),
    ('a\nb', 'FAIL'), ('a\tb', 'FAIL'), ('x🙂', 'FAIL'), ('e\u0301', 'FAIL'),
    (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_tag_characters(text, expected):
    resource = target('window', 'AWS::SSM::MaintenanceWindow', Tags=[{'Key': 'name', 'Value': text}])
    results = run_resource_checks(linked_design(resource), resource)
    assert results[-1]['path'] == '/properties/Tags/0/Value'
    assert results[-1]['verdict'] == expected


def test_unresolved_tags():
    resource = target('window', 'AWS::SSM::MaintenanceWindow', Tags=UNKNOWN)
    assert run_resource_checks(linked_design(resource), resource)[0]['verdict'] == 'NEEDS_REVIEW'
