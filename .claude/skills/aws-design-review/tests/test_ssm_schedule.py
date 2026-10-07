import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(**properties):
    main = target('association', 'AWS::SSM::Association', **properties)
    return {r['rule_id']: r['verdict'] for r in run_resource_checks(linked_design(main), main)}


@pytest.mark.parametrize('expression,expected', [
    ('rate(29 minutes)', 'FAIL'), ('rate(30 minutes)', 'PASS'), ('rate(1 hour)', 'PASS'),
    ('rate(1 hours)', 'FAIL'), ('rate(5 hour)', 'FAIL'), ('rate(30 days)', 'PASS'),
    ('rate(31 days)', 'FAIL'), ('rate(743 hours)', 'PASS'), ('rate(744 hours)', 'FAIL'),
    ('rate(44639 minutes)', 'PASS'), ('rate(44640 minutes)', 'FAIL'),
    ('rate(0 days)', 'FAIL'), ('rate(-1 days)', 'FAIL'), ('rate(1.5 hours)', 'NEEDS_REVIEW'),
    ('rate(${days} days)', 'NEEDS_REVIEW'), (UNKNOWN, 'NEEDS_REVIEW'),
    ('cron(0 0 ? * MON *)', 'NOT_APPLICABLE'), ('at(2026-10-10T00:00:00)', 'NOT_APPLICABLE'),
])
def test_rate_interval(expression, expected):
    assert check(ScheduleExpression=expression)['SSM_ASSOCIATION_RATE_INTERVAL'] == expected


@pytest.mark.parametrize('expression,apply,offset,expected', [
    ('cron(0 0 ? * MON *)', True, 2, 'PASS'),
    ('cron(0 0 ? * MON *)', False, 2, 'FAIL'),
    ('cron(0 0 ? * MON *)', UNKNOWN, 2, 'NEEDS_REVIEW'),
    ('cron(0 0 ? * MON *)', True, UNKNOWN, 'NEEDS_REVIEW'),
    ('rate(1 day)', True, 2, 'FAIL'), ('at(2026-10-10T00:00:00)', True, 2, 'FAIL'),
    (UNKNOWN, True, 2, 'NEEDS_REVIEW'), ('unknown', True, 2, 'NEEDS_REVIEW'),
])
def test_offset_prerequisites(expression, apply, offset, expected):
    assert check(ScheduleExpression=expression, ApplyOnlyAtCronInterval=apply,
                 ScheduleOffset=offset)['SSM_ASSOCIATION_OFFSET_CRON'] == expected


def test_absent_offset_and_required_flags():
    assert 'SSM_ASSOCIATION_OFFSET_CRON' not in check(ScheduleExpression='rate(30 minutes)')
    assert check(ScheduleOffset=2)['SSM_ASSOCIATION_OFFSET_CRON'] == 'FAIL'
    assert check(ScheduleOffset=2, ScheduleExpression='cron(0 0 ? * MON *)')['SSM_ASSOCIATION_OFFSET_CRON'] == 'FAIL'
