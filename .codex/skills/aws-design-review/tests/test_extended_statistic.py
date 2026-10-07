import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('stat,expected',[
    ('p0.0','PASS'),('p100','PASS'),('p99.99','PASS'),('p100.01','FAIL'),('p-1','FAIL'),
    ('tm90','PASS'),('tc0','PASS'),('ts100','PASS'),('wm99.9','PASS'),('tm101','FAIL'),
    ('IQM','PASS'),('tm1.1234567890','PASS'),('tm1.12345678901','FAIL'),
    ('TM(2%:98%)','PASS'),('TM(150:1000)','PASS'),('PR(:300)','PASS'),
    ('TC(0.005:0.030)','PASS'),('TS(80%:)','PASS'),('WM(10%:90%)','PASS'),
    ('TM(:95%)','PASS'),('TC(:0.5)','PASS'),('PR(100:2000)','PASS'),('PR(10:)','PASS'),
    ('TM(0%:100%)','PASS'),('TM(:100.1%)','FAIL'),('WM(101%:)','FAIL'),
    ('TM(0.12345678901%:99%)','FAIL'),('TM(100:200)','PASS'),
    ('TM(90%:10%)','NEEDS_REVIEW'),('TM(10:10)','NEEDS_REVIEW'),
    ('TM(10%:100)','NEEDS_REVIEW'),('TM(:)','NEEDS_REVIEW'),
    ('PR(10%:20%)','NEEDS_REVIEW'),('TM(-1:2)','NEEDS_REVIEW'),
    ('TM(1e2:2e2)','NEEDS_REVIEW'),('tm(10%:90%)','NEEDS_REVIEW'),
    ('future','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),('${Statistic}','NEEDS_REVIEW'),
])
def test_extended_statistic_subset(stat,expected):
    main=target('alarm','AWS::CloudWatch::Alarm',MetricName='Latency',ExtendedStatistic=stat)
    row=next(r for r in run_resource_checks(linked_design(main),main) if r['rule_id']=='CLOUDWATCH_EXTENDED_STATISTIC_KNOWN')
    assert row['verdict']==expected
