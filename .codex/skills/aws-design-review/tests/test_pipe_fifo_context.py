import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.pipes.pipe import evaluate_pipes_pipe
from aws_design_sheet.checks.quicksight.dashboard_theme_account import evaluate_quicksight_dashboard_theme_account
from aws_design_sheet.checks.registry import combine
pipe_targets_checks = combine(evaluate_pipes_pipe, evaluate_quicksight_dashboard_theme_account)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('case',['default','fifo','unknown','queue_template','pipe_template','scope','dynamic'])
def test_fifo_default_context(case):
    r=target('main','AWS::Pipes::Pipe',Target='queue',TargetParameters={'SqsQueueParameters':{'MessageDeduplicationId':'$.id' if case=='dynamic' else 'token'}})
    q=target('queue','AWS::SQS::Queue',**({'FifoQueue':True} if case=='fifo' else {'FifoQueue':UNKNOWN} if case=='unknown' else {}))
    d=linked_design(r,[q],[('Target','queue')])
    if case=='queue_template':q.template=TemplateContext(state='UNRESOLVED')
    if case=='pipe_template':r.template=TemplateContext(state='UNRESOLVED')
    if case=='scope':q.scope.region='us-east-1'
    expected='FAIL' if case in ('default','dynamic') else 'PASS' if case=='fifo' else 'NEEDS_REVIEW'
    assert pipe_targets_checks(d,r)[0]['verdict']==expected
