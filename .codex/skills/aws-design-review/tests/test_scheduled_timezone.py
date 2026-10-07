import pytest
from aws_design_sheet.checks.autoscaling import scheduled_timezone as timezone
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('name,expected',[
    ('Asia/Tokyo','PASS'),('Etc/GMT+9','PASS'),('Pacific/Tahiti','PASS'),
    ('Etc/UTC','PASS'),('US/Eastern','NEEDS_REVIEW'),('UTC','NEEDS_REVIEW'),
    ('asia/tokyo','FAIL'),('Tokyo','FAIL'),('../UTC','FAIL'),
    (UNKNOWN,'NEEDS_REVIEW'),('{{resolve:ssm:tz}}','NEEDS_REVIEW')])
def test_scheduled_timezone(name,expected):
    main=target('action','AWS::AutoScaling::ScheduledAction',TimeZone=name)
    assert next(r['verdict'] for r in run_resource_checks(linked_design(main),main) if r['rule_id']=='AUTOSCALING_SCHEDULE_TIMEZONE')==expected


def test_missing_pinned_dataset(monkeypatch):
    monkeypatch.setattr(timezone,'canonical_timezone_names',lambda:None)
    main=target('action','AWS::AutoScaling::ScheduledAction',TimeZone='Asia/Tokyo')
    assert timezone.scheduled_timezone(linked_design(main),main)[0]['verdict']=='NEEDS_REVIEW'


def test_absent_timezone():
    main=target('action','AWS::AutoScaling::ScheduledAction')
    assert timezone.scheduled_timezone(linked_design(main),main)==[]
