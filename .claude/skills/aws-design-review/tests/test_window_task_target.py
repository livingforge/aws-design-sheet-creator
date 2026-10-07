import pytest
from aws_design_sheet.checks.ssm.schedule import window_task_target
from test_autoscaling_group_and_scaling_policy import target, linked_design


@pytest.mark.parametrize('kind,expected', [('RUN_COMMAND','AWS::SSM::Document'),
    ('AUTOMATION','AWS::SSM::Document'), ('LAMBDA','AWS::Lambda::Function'),
    ('STEP_FUNCTIONS','AWS::StepFunctions::StateMachine')])
@pytest.mark.parametrize('other', ['AWS::SSM::Document','AWS::Lambda::Function','AWS::StepFunctions::StateMachine'])
def test_task_target_type(kind, expected, other):
    task = target('task','AWS::SSM::MaintenanceWindowTask',TaskType=kind,TaskArn={'Ref':'other'})
    other_resource = target('other',other)
    data = linked_design(task,[other_resource],[('TaskArn','other')])
    assert window_task_target(data,task)[0]['verdict'] == ('PASS' if other == expected else 'FAIL')
    data.relations[0].condition = 'UseTask'
    assert window_task_target(data,task)[0]['verdict'] == 'NEEDS_REVIEW'


def test_literal_and_unknown_task_type():
    for kind in ('LAMBDA','FUTURE'):
        task = target('task','AWS::SSM::MaintenanceWindowTask',TaskType=kind,TaskArn='function')
        assert window_task_target(linked_design(task),task)[0]['verdict'] == 'NEEDS_REVIEW'
