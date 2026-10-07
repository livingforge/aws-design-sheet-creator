import pytest
from aws_design_sheet.checks.events.input import object_key_verdict
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(transformer):
    main = target('rule', 'AWS::Events::Rule', Targets=[{'InputTransformer': transformer}])
    return {r['rule_id']: r['verdict'] for r in run_resource_checks(linked_design(main), main)}


@pytest.mark.parametrize('path,expected', [('$.detail.instance-id', 'PASS'), ('$.detail.name_value', 'PASS'),
    ('$.detail.part/name', 'PASS'), ('$.detail.*', 'PASS'), ('$.resources[0]', 'NEEDS_REVIEW'),
    ("$['detail']", 'NEEDS_REVIEW'), ('$.detail..name', 'NEEDS_REVIEW'),
    ('$.detail[?(@.x)]', 'NEEDS_REVIEW'), ('${Path}', 'NEEDS_REVIEW'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_event_paths(path, expected):
    assert check({'InputPathsMap': {'value': path}})['EVENTS_INPUT_PATH_SYNTAX'] == expected


@pytest.mark.parametrize('template,expected', [
    ('{"instance":<instance>}', 'PASS'), ('{"instance":"<instance>"}', 'PASS'),
    ('{"<instance>":1}', 'FAIL'), ('{"prefix-<instance>":1}', 'FAIL'),
    ('{<instance>:1}', 'FAIL'), ('{<unknown>:1}', 'NEEDS_REVIEW'),
    ('{"nested":[{"<instance>":1}]}', 'FAIL'), ('{"<aws.events.rule-name>":1}', 'FAIL'),
    ('{"<unknown>":1}', 'NEEDS_REVIEW'), ('{"instance":', 'NEEDS_REVIEW'),
    ('"instance <instance>"', 'NOT_APPLICABLE'), ('{"key":"escaped \\" quote"}', 'PASS'),
    ('{"key":1,"key":2}', 'NEEDS_REVIEW'), ('{"key":NaN}', 'NEEDS_REVIEW'),
    (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_placeholder_keys(template, expected):
    assert check({'InputPathsMap': {'instance': '$.detail.instance'}, 'InputTemplate': template})['EVENTS_TEMPLATE_PLACEHOLDER_KEYS'] == expected


def test_unknown_map_and_placeholder_like_static_key():
    assert object_key_verdict('{"<instance>":1}', None) == 'NEEDS_REVIEW'
    assert object_key_verdict('{"<aws.events.event.json>":1}', None) == 'FAIL'
    assert object_key_verdict('{"angle<not a variable>":1}', set()) == 'PASS'
    assert check({'InputPathsMap': UNKNOWN, 'InputTemplate': '{"key":1}'})['EVENTS_TEMPLATE_PLACEHOLDER_KEYS'] == 'NEEDS_REVIEW'
