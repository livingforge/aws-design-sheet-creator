import pytest
from aws_design_sheet.checks.synthetics.canary_rate import evaluate_synthetics_canary_rate
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('expression,timeout,rate,want',[
    ('rate(1 minute)',60,'PASS','PASS'),('rate(1 minute)',61,'PASS','FAIL'),
    ('rate(10 minutes)',600,'PASS','PASS'),('rate(10 minutes)',601,'PASS','FAIL'),
    ('rate(1 hour)',840,'PASS','PASS'),('rate(60 minutes)',840,'PASS','PASS'),
    ('rate(61 minutes)',10,'FAIL','NEEDS_REVIEW'),('rate(2 hour)',10,'FAIL','NEEDS_REVIEW'),
    ('rate(0 minute)',840,'PASS','NOT_APPLICABLE'),('rate(0 hour)',840,'PASS','NOT_APPLICABLE'),
    ('rate(0 minutes)',10,'NEEDS_REVIEW','NEEDS_REVIEW'),('rate(1 minutes)',10,'NEEDS_REVIEW','NEEDS_REVIEW'),
    ('cron(0 * * * ? *)',10,'NEEDS_REVIEW','NEEDS_REVIEW'),(UNKNOWN,10,'NEEDS_REVIEW','NEEDS_REVIEW'),
    ('rate(1 minute)',UNKNOWN,'PASS','NEEDS_REVIEW'),('rate(1 minute)',True,'PASS','NEEDS_REVIEW'),
    ('rate(01 minute)',10,'NEEDS_REVIEW','NEEDS_REVIEW')])
def test_interval(expression,timeout,rate,want):
    r=target('canary','AWS::Synthetics::Canary',Schedule={'Expression':expression},RunConfig={'TimeoutInSeconds':timeout})
    assert [f['verdict'] for f in evaluate_synthetics_canary_rate(linked_design(r),r)]==[rate,want]


def test_omitted_timeout_is_service_default():
    r=target('canary','AWS::Synthetics::Canary',Schedule={'Expression':'rate(1 minute)'})
    assert evaluate_synthetics_canary_rate(linked_design(r),r)[1]['verdict']=='NOT_APPLICABLE'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    r=target('canary','AWS::Synthetics::Canary',Schedule={'Expression':'rate(1 minute)'},RunConfig={'TimeoutInSeconds':60});d=linked_design(r);root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='SYNTHETICS_TIMEOUT_INTERVAL' and f['verdict']=='PASS' for f in results)
