import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(**props):
    main=target('query','AWS::Logs::ScheduledQuery',**props)
    return run_resource_checks(linked_design(main),main)


@pytest.mark.parametrize('language,expected',[('CWLI','PASS'),('SQL','PASS'),('PPL','PASS'),('sql','FAIL'),('Future','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_query_language(language,expected):
    row=check(QueryLanguage=language)[0]
    assert row['verdict']==expected
    assert row['severity']=='WARNING'


@pytest.mark.parametrize('epoch,expected',[(0,'PASS'),(1700000000,'PASS'),(-1,'FAIL'),(1.5,'PASS'),(UNKNOWN,'NEEDS_REVIEW'),(True,'NEEDS_REVIEW')])
def test_epoch_range(epoch,expected):
    assert check(ScheduleStartTime=epoch)[0]['verdict']==expected


@pytest.mark.parametrize('start,end,expected',[(0,1,'PASS'),(10,1,'FAIL'),(10,10,'NEEDS_REVIEW'),(UNKNOWN,10,'NEEDS_REVIEW')])
def test_time_window(start,end,expected):
    row=next(r for r in check(ScheduleStartTime=start,ScheduleEndTime=end) if r['rule_id']=='LOGS_SCHEDULED_QUERY_TIME_WINDOW')
    assert row['verdict']==expected
    assert row['severity']=='WARNING'


def test_omitted_time_bounds_are_not_invented():
    assert not any(r['rule_id']=='LOGS_SCHEDULED_QUERY_TIME_WINDOW' for r in check(ScheduleStartTime=1))
