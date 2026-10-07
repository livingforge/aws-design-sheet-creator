import pytest
from pathlib import Path
from aws_design_sheet.checks.kinesisanalytics.output_limits import evaluate_kinesisanalytics_output_limits, SPECS
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_config_pipeline import nested


@pytest.mark.parametrize('path,low,high,pattern',SPECS)
@pytest.mark.parametrize('case',['minimum','maximum','over','empty','pattern','unknown','dynamic'])
def test_bounds(path,low,high,pattern,case):
    prefix='arn:' if pattern==r'arn:.*' else ''
    raw=prefix+'a'*max(1,len(prefix)==0) if case=='minimum' else prefix+'a'*(high-len(prefix)) if case=='maximum' else prefix+'a'*(high+1-len(prefix)) if case=='over' else '' if case=='empty' else 'bad value' if case=='pattern' else UNKNOWN if case=='unknown' else '${value}'
    props=nested(path.split('/'),raw);r=target('main','AWS::KinesisAnalytics::ApplicationOutput',**props)
    rows=evaluate_kinesisanalytics_output_limits(linked_design(r),r)
    expected='NEEDS_REVIEW' if case in ('unknown','dynamic') else 'FAIL' if case in ('over','empty') or case=='pattern' and pattern is not None else 'PASS'
    assert len(rows)==1 and rows[0]['verdict']==expected


def test_no_strengthening_of_documented_arn_pattern():
    r=target('main','AWS::KinesisAnalytics::ApplicationOutput',Output={'LambdaOutput':{'ResourceARN':'arn:'}})
    assert evaluate_kinesisanalytics_output_limits(linked_design(r),r)[0]['verdict']=='PASS'


def test_checker_dispatch():
    r=target('main','AWS::KinesisAnalytics::ApplicationOutput',ApplicationName='bad name')
    root=Path(__file__).resolve().parents[1]
    rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='KINESIS_ANALYTICS_OUTPUT_STRING_LIMITS' and f['verdict']=='FAIL' for f in rows)
