from pathlib import Path
import pytest
from aws_design_sheet.checks.sagemaker.inference_experiments import evaluate_sagemaker_inference_experiments
from aws_design_sheet.checks.pinpoint.apns_auth_method import evaluate_pinpoint_apns_auth_method
from aws_design_sheet.checks.registry import combine
inference_windows_checks = combine(evaluate_sagemaker_inference_experiments, evaluate_pinpoint_apns_auth_method)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('end,verdict',[
 ('2026-01-31T00:00:00Z','PASS'),('2026-01-31T00:00:00.000001Z','FAIL'),
 ('2026-01-31T09:00:00+09:00','PASS'),('2026-01-31T09:00:01+09:00','FAIL'),
 ('2026-01-01T00:00:00Z','PASS'),('2025-12-31T00:00:00Z','NEEDS_REVIEW'),
 ('2026-02-30T00:00:00Z','NEEDS_REVIEW'),('2026-01-31','NEEDS_REVIEW'),
 ('2026-01-31T00:00:00','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),('${end}','NEEDS_REVIEW'),
 ('9999-12-31T23:59:59-23:59','NEEDS_REVIEW')])
def test_duration(end,verdict):
 r=target('main','AWS::SageMaker::InferenceExperiment',Schedule={'StartTime':'2026-01-01T00:00:00Z','EndTime':end})
 assert inference_windows_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('schedule',[{},UNKNOWN,{'EndTime':'2026-01-31T00:00:00Z'}])
def test_missing_start(schedule):
 r=target('main','AWS::SageMaker::InferenceExperiment',Schedule=schedule)
 assert inference_windows_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('raw,verdict',[([],'FAIL'),([{}],'PASS'),([{}]*10,'PASS'),([{}]*11,'FAIL'),([UNKNOWN]*11,'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_alarms(raw,verdict):
 r=target('main','AWS::SageMaker::Endpoint',DeploymentConfig={'AutoRollbackConfiguration':{'Alarms':raw}})
 assert inference_windows_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('raw,verdict',[('key','PASS'),('certificate','PASS'),('KEY','FAIL'),('TOKEN','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${method}','NEEDS_REVIEW')])
def test_auth(raw,verdict):
 r=target('main','AWS::Pinpoint::APNSChannel',DefaultAuthenticationMethod=raw)
 assert inference_windows_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('kind',['AWS::SageMaker::InferenceExperiment','AWS::SageMaker::Endpoint','AWS::Pinpoint::APNSChannel'])
def test_absent(kind):
 r=target('main',kind);assert not inference_windows_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::SageMaker::InferenceExperiment',Schedule={'StartTime':'2026-01-01T00:00:00Z','EndTime':'2026-02-01T00:00:00Z'})
 root=Path(__file__).resolve().parents[1]
 results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='SAGEMAKER_EXPERIMENT_DURATION' and f['verdict']=='FAIL' for f in results)
