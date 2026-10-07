import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(schedule, duration=None):
    props = {'ScheduleExpression': schedule}
    if duration is not None:
        props['Duration'] = duration
    resource = target('rotation', 'AWS::SecretsManager::RotationSchedule', RotationRules=props)
    return {r['rule_id']: r['verdict'] for r in run_resource_checks(linked_design(resource), resource)}


@pytest.mark.parametrize('schedule,expected', [
    ('rate(4 hours)', 'PASS'), ('rate(1 day)', 'PASS'), ('rate(999 days)', 'PASS'),
    ('rate(3 hours)', 'FAIL'), ('rate(1000 days)', 'FAIL'), ('rate(0 days)', 'FAIL'),
    ('rate(23976 hours)', 'PASS'), ('rate(23977 hours)', 'FAIL'),
    ('rate(1 minute)', 'NEEDS_REVIEW'), (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_rate_interval(schedule, expected):
    assert check(schedule)['SECRET_ROTATION_RATE_INTERVAL'] == expected


@pytest.mark.parametrize('schedule,duration,expected', [
    ('rate(4 hours)', '4h', 'PASS'), ('rate(4 hours)', '5h', 'FAIL'),
    ('rate(1 day)', '24h', 'PASS'), ('rate(2 days)', '25h', 'FAIL'),
    ('rate(5 hours)', '2h', 'NEEDS_REVIEW'), ('rate(4 hours)', '0h', 'FAIL'),
    ('rate(4 hours)', 'PT1H', 'NEEDS_REVIEW'), ('rate(4 hours)', UNKNOWN, 'NEEDS_REVIEW'),
    ('rate(4 hours)', None, 'PASS'), ('rate(1 day)', None, 'PASS'),
    ('cron(0 22 * * ? *)', '2h', 'PASS'), ('cron(0 22 * * ? *)', '3h', 'FAIL'),
    ('cron(0 2/10 * * ? *)', '2h', 'PASS'), ('cron(0 2/10 * * ? *)', '3h', 'FAIL'),
    ('cron(0 /8 * * ? *)', '8h', 'PASS'), ('cron(0 8/8 * * ? *)', None, 'PASS'),
    ('cron(0 8 * * ? *)', None, 'PASS'), ('cron(0 8,16 * * ? *)', '1h', 'NEEDS_REVIEW'),
])
def test_rotation_window(schedule, duration, expected):
    assert check(schedule, duration)['SECRET_ROTATION_WINDOW'] == expected


@pytest.mark.parametrize('schedule,expected', [
    ('cron(0 8 * * ? *)', 'PASS'), ('cron(0 8 ? * MON *)', 'PASS'),
    ('cron(1 8 * * ? *)', 'FAIL'), ('cron(0 8 * * ? 2026)', 'FAIL'),
    ('cron(0 8 * * MON *)', 'FAIL'), ('cron(0 8 * * *)', 'FAIL'),
])
def test_required_cron_fields(schedule, expected):
    assert check(schedule)['SECRET_ROTATION_CRON_FIELDS'] == expected
