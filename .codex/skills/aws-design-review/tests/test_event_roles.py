import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN

ROLE='arn:aws:iam::111111111111:role/events'


@pytest.mark.parametrize('arn',[
    'arn:aws:kinesis:ap-northeast-1:111111111111:stream/events',
    'arn:aws:states:ap-northeast-1:111111111111:stateMachine:workflow',
])
@pytest.mark.parametrize('role,root,expected',[(None,False,'FAIL'),(ROLE,False,'PASS'),(ROLE,True,'PASS'),(UNKNOWN,False,'NEEDS_REVIEW')])
def test_target_invocation_role(arn,role,root,expected):
    entry={'Id':'target','Arn':arn}
    props={'Targets':[entry]}
    if role is not None:
        (props if root else entry)['RoleArn']=role
    main=target('rule','AWS::Events::Rule',**props)
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
    assert rows['EVENTS_TARGET_INVOCATION_ROLE']==expected


def test_api_gateway_and_unknown_targets_do_not_require_roles_from_old_docs():
    main=target('rule','AWS::Events::Rule',Targets=[{'Id':'api','Arn':'arn:aws:execute-api:ap-northeast-1:111111111111:api/stage/GET/path'},{'Id':'unknown','Arn':UNKNOWN}])
    assert all(r['rule_id']!='EVENTS_TARGET_INVOCATION_ROLE' for r in run_resource_checks(linked_design(main),main))


def test_linked_target_and_role_presence():
    main=target('rule','AWS::Events::Rule',Targets=[{'Id':'stream','Arn':{'Ref':'stream'},'RoleArn':{'Ref':'role'}}])
    stream=target('stream','AWS::Kinesis::Stream')
    role=target('role','AWS::IAM::Role')
    data=linked_design(main,[stream,role],[('Targets/0/Arn','stream'),('Targets/0/RoleArn','role')])
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}
    assert rows['EVENTS_TARGET_INVOCATION_ROLE']=='PASS'
    data.relations[1].condition='optional'
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}
    assert rows['EVENTS_TARGET_INVOCATION_ROLE']=='NEEDS_REVIEW'
