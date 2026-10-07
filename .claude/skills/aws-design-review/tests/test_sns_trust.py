import json
import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def statement(principal='sns.amazonaws.com',**kwargs):
    return {'Effect':'Allow','Principal':{'Service':principal},'Action':'sts:AssumeRole',**kwargs}


@pytest.mark.parametrize('document,expected',[
    ({'Statement':[statement()]},'PASS'),
    ({'Statement':statement()},'PASS'),
    (json.dumps({'Statement':[statement()]}),'PASS'),
    ({'Statement':[statement('ec2.amazonaws.com')]},'FAIL'),
    ({'Statement':[statement(Effect='Deny')]},'FAIL'),
    ({'Statement':[statement(),statement(Effect='Deny')]},'FAIL'),
    ({'Statement':[statement(Condition={'StringEquals':{'aws:SourceAccount':'111111111111'}})]},'NEEDS_REVIEW'),
    ({'Statement':[statement(Action='sts:TagSession')]},'FAIL'),
    ({'Statement':[statement(Principal='*')]},'NEEDS_REVIEW'),
    ({'Statement':[statement(Principal={'Service':UNKNOWN})]},'NEEDS_REVIEW'),
    ({'Statement':[statement(),UNKNOWN]},'NEEDS_REVIEW'),
    ({'Statement':[statement(Action=['sts:AssumeRole','sts:TagSession'])]},'PASS'),
    ({'Statement':[statement(Action='STS:assumerole')]},'PASS'),
    ({'Statement':[statement(Action='sts:*')]},'PASS'),
    ({'Statement':[statement(Action='sts:Assume*')]},'NEEDS_REVIEW'),
    ('{"Statement":[],"Statement":[]}','NEEDS_REVIEW'),
    (UNKNOWN,'NEEDS_REVIEW'),
])
def test_explicit_sns_trust(document,expected):
    main=target('subscription','AWS::SNS::Subscription',Protocol='firehose',SubscriptionRoleArn={'Ref':'role'})
    role=target('role','AWS::IAM::Role',AssumeRolePolicyDocument=document)
    data=linked_design(main,[role],[('SubscriptionRoleArn','role')])
    row=next(r for r in run_resource_checks(data,main) if r['rule_id']=='SNS_FIREHOSE_ROLE_TRUST')
    assert row['verdict']==expected
    data.relations[0].condition='optional'
    row=next(r for r in run_resource_checks(data,main) if r['rule_id']=='SNS_FIREHOSE_ROLE_TRUST')
    assert row['verdict']=='NEEDS_REVIEW'


STREAM='arn:aws:firehose:ap-northeast-1:111111111111:deliverystream/events'


@pytest.mark.parametrize('statements,expected',[
    ([{'Effect':'Allow','Action':'firehose:PutRecord','Resource':STREAM}],'PASS'),
    ([{'Effect':'Allow','Action':['firehose:PutRecord','firehose:PutRecordBatch'],'Resource':[STREAM]}],'PASS'),
    ([{'Effect':'Allow','Action':'firehose:*','Resource':'*'}],'PASS'),
    ([{'Effect':'Deny','Action':'firehose:PutRecord','Resource':STREAM}],'FAIL'),
    ([{'Effect':'Allow','Action':'firehose:PutRecordBatch','Resource':STREAM}],'NEEDS_REVIEW'),
    ([{'Effect':'Allow','Action':'firehose:PutRecord','Resource':STREAM+'other'}],'NEEDS_REVIEW'),
    ([{'Effect':'Allow','Action':'firehose:PutRecord','Resource':STREAM,'Condition':{}}],'NEEDS_REVIEW'),
    ([{'Effect':'Allow','Action':'firehose:Put*','Resource':STREAM}],'NEEDS_REVIEW'),
    ([{'Effect':'Allow','Action':'firehose:PutRecord','Resource':UNKNOWN}],'NEEDS_REVIEW'),
    ([], 'NEEDS_REVIEW'),
])
def test_declared_firehose_write(statements,expected):
    main=target('subscription','AWS::SNS::Subscription',Protocol='firehose',Endpoint=STREAM,SubscriptionRoleArn={'Ref':'role'})
    role=target('role','AWS::IAM::Role',Policies=[{'PolicyName':'delivery','PolicyDocument':{'Statement':statements}}])
    data=linked_design(main,[role],[('SubscriptionRoleArn','role')])
    row=next(r for r in run_resource_checks(data,main) if r['rule_id']=='SNS_FIREHOSE_DECLARED_WRITE')
    assert row['verdict']==expected
