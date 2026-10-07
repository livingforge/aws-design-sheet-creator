from pathlib import Path
import pytest
from aws_design_sheet.checks.pipes.pipe import evaluate_pipes_pipe
from aws_design_sheet.checks.quicksight.dashboard_theme_account import evaluate_quicksight_dashboard_theme_account
from aws_design_sheet.checks.registry import combine
pipe_targets_checks = combine(evaluate_pipes_pipe, evaluate_quicksight_dashboard_theme_account)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('mode',['sync','dedup'])
@pytest.mark.parametrize('case',['pass','fail','unknown','omitted','external','duplicate','conditional','input_unknown','dynamic','wrong_type'])
def test_targets(mode,case):
    sync=mode=='sync'
    raw=UNKNOWN if case=='input_unknown' else '${value}' if case=='dynamic' else 'REQUEST_RESPONSE' if sync else 'token'
    params={'StepFunctionStateMachineParameters':{'InvocationType':raw}} if sync else {'SqsQueueParameters':{'MessageDeduplicationId':raw}}
    r=target('main','AWS::Pipes::Pipe',Target='target',TargetParameters=params)
    kind='EXPRESS' if sync else True
    if case=='fail':kind='STANDARD' if sync else False
    if case=='unknown':kind=UNKNOWN
    t=target('target','AWS::StepFunctions::StateMachine' if sync else 'AWS::SQS::Queue',**({} if case=='omitted' else {'StateMachineType' if sync else 'FifoQueue':kind}))
    if case=='wrong_type':t.type='AWS::S3::Bucket'
    links=[] if case=='external' else [('Target','target')]
    if case=='duplicate':links.append(('Target','target'))
    d=linked_design(r,[t],links)
    if case=='conditional':d.relations[0].condition='condition'
    assert pipe_targets_checks(d,r)[0]['verdict']==('PASS' if case=='pass' else 'FAIL' if case=='fail' or case=='omitted' and not sync else 'NEEDS_REVIEW')


@pytest.mark.parametrize('account,arn,verdict',[
    ('111111111111','arn:aws:quicksight:ap-northeast-1:111111111111:theme/test','PASS'),
    ('222222222222','arn:aws:quicksight:ap-northeast-1:111111111111:theme/test','FAIL'),
    ('222222222222','arn:aws:quicksight:ap-northeast-1:222222222222:theme/test','PASS'),
    (UNKNOWN,'arn:aws:quicksight:ap-northeast-1:111111111111:theme/test','NEEDS_REVIEW'),
    ('111111111111',UNKNOWN,'NEEDS_REVIEW'),
    ('111111111111','${theme}','NEEDS_REVIEW'),
    ('111111111111','arn:aws:quicksight:ap-northeast-1::theme/CLASSIC','NEEDS_REVIEW'),
    ('111111111111','arn:aws:quicksight:ap-northeast-1:222222222222:template/test','NEEDS_REVIEW'),
])
def test_theme(account,arn,verdict):
    r=target('main','AWS::QuickSight::Dashboard',AwsAccountId=account,ThemeArn=arn)
    assert pipe_targets_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('kind',['AWS::Pipes::Pipe','AWS::QuickSight::Dashboard'])
def test_absent(kind):
    r=target('main',kind)
    assert not pipe_targets_checks(linked_design(r),r)


def test_checker():
    r=target('main','AWS::QuickSight::Dashboard',AwsAccountId='222222222222',ThemeArn='arn:aws:quicksight:ap-northeast-1:111111111111:theme/test')
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='QUICKSIGHT_DASHBOARD_THEME_ACCOUNT' and f['verdict']=='FAIL' for f in results)
