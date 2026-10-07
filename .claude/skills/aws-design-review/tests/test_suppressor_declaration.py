import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('kind', ['Alarm', 'CompositeAlarm'])
@pytest.mark.parametrize('change,expected', [
    ('none', 'PASS'), ('region', 'NEEDS_REVIEW'), ('account', 'NEEDS_REVIEW'),
    ('condition', 'NEEDS_REVIEW'), ('unknown', 'NEEDS_REVIEW'),
    ('wrong_type', 'NEEDS_REVIEW'), ('no_link', 'NEEDS_REVIEW'),
])
def test_suppressor_declaration(kind, change, expected):
    main = target('main', 'AWS::CloudWatch::CompositeAlarm', ActionsSuppressor={'Ref': 'alarm'})
    alarm = target('alarm', 'AWS::CloudWatch::' + kind)
    if change == 'region':
        alarm.scope.region = 'us-west-2'
    if change == 'account':
        alarm.scope.account = '222222222222'
    if change == 'wrong_type':
        alarm.type = 'AWS::SNS::Topic'
    data = linked_design(main, [alarm], [('ActionsSuppressor', 'alarm')])
    if change == 'condition':
        data.relations[0].condition = 'optional'
    if change == 'unknown':
        main.scope.account = alarm.scope.account = 'unknown'
    if change == 'no_link':
        data.relations = []
    rows = [r for r in run_resource_checks(data, main) if r['rule_id'] == 'CLOUDWATCH_SUPPRESSOR_DECLARATION']
    assert [r['verdict'] for r in rows] == [expected]


@pytest.mark.parametrize('raw', ['external-alarm', UNKNOWN])
def test_external_suppressor(raw):
    main = target('main', 'AWS::CloudWatch::CompositeAlarm', ActionsSuppressor=raw)
    rows = run_resource_checks(linked_design(main), main)
    assert next(r['verdict'] for r in rows if r['rule_id'] == 'CLOUDWATCH_SUPPRESSOR_DECLARATION') == 'NEEDS_REVIEW'


def test_absent_suppressor():
    main = target('main', 'AWS::CloudWatch::CompositeAlarm')
    assert not any(r['rule_id'] == 'CLOUDWATCH_SUPPRESSOR_DECLARATION'
                   for r in run_resource_checks(linked_design(main), main))
