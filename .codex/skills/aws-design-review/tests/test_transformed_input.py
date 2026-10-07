import pytest
from aws_design_sheet.models import Relation
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('kind',['MetricFilter','SubscriptionFilter'])
@pytest.mark.parametrize('enabled,conditional,region,expected',[
    (True,False,'ap-northeast-1','PASS'),(True,True,'ap-northeast-1','NEEDS_REVIEW'),
    (True,False,'us-west-2','NEEDS_REVIEW'),(False,False,'ap-northeast-1','NEEDS_REVIEW'),
    (UNKNOWN,False,'ap-northeast-1','NEEDS_REVIEW'),
])
def test_declared_same_group_transformer(kind,enabled,conditional,region,expected):
    main=target('filter','AWS::Logs::'+kind,ApplyOnTransformedLogs=enabled,LogGroupName={'Ref':'group'})
    group=target('group','AWS::Logs::LogGroup')
    transformer=target('transformer','AWS::Logs::Transformer',LogGroupIdentifier={'Ref':'group'})
    transformer.scope.region=region
    data=linked_design(main,[group,transformer],[('LogGroupName','group')])
    data.relations.append(Relation(id='transformer-group',source_resource_id='transformer',source_path='/properties/LogGroupIdentifier',target_resource_id='group',evidence_ids=['e1'],condition='optional' if conditional else None))
    assert run_resource_checks(data,main)[0]['verdict']==expected


def test_absent_transformer_does_not_disprove_account_level_transformer():
    main=target('filter','AWS::Logs::MetricFilter',ApplyOnTransformedLogs=True,LogGroupName={'Ref':'group'})
    group=target('group','AWS::Logs::LogGroup')
    data=linked_design(main,[group],[('LogGroupName','group')])
    assert run_resource_checks(data,main)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('kind',['MetricFilter','SubscriptionFilter'])
@pytest.mark.parametrize('criteria,name,scope,expected',[
    (None,None,None,'PASS'),(None,UNKNOWN,'ALL','PASS'),
    ('LogGroupNamePrefix="/aws/"','/aws/lambda/app','ALL','PASS'),
    ('LogGroupNamePrefix = "/aws/"','/aws/ecs',None,'PASS'),
    ('LogGroupNamePrefix="/aws/"','/other',None,'NEEDS_REVIEW'),
    ('LogGroupNamePrefix="/AWS/"','/aws/ecs',None,'NEEDS_REVIEW'),
    ('LogGroupNamePrefix="/aws/"',UNKNOWN,None,'NEEDS_REVIEW'),
    (UNKNOWN,'/aws/ecs',None,'NEEDS_REVIEW'),
    ('LogGroupName IN ["/aws/ecs"]','/aws/ecs',None,'NEEDS_REVIEW'),
    (None,'/aws/ecs',UNKNOWN,'NEEDS_REVIEW'),
    (None,'/aws/ecs','future','NEEDS_REVIEW'),
])
def test_account_transformer_selection(kind,criteria,name,scope,expected):
    main=target('filter','AWS::Logs::'+kind,ApplyOnTransformedLogs=True,LogGroupName={'Ref':'group'})
    group=target('group','AWS::Logs::LogGroup',**({'LogGroupName':name} if name is not None else {}))
    props={'PolicyType':'TRANSFORMER_POLICY'}
    if criteria is not None:props['SelectionCriteria']=criteria
    if scope is not None:props['Scope']=scope
    policy=target('policy','AWS::Logs::AccountPolicy',**props)
    data=linked_design(main,[group,policy],[('LogGroupName','group')])
    assert run_resource_checks(data,main)[0]['verdict']==expected


@pytest.mark.parametrize('change',['other-region','other-account','unknown-account','unknown-region','wrong-type','conditional-group'])
def test_account_transformer_uncertain_identity(change):
    main=target('filter','AWS::Logs::MetricFilter',ApplyOnTransformedLogs=True,LogGroupName={'Ref':'group'})
    group=target('group','AWS::Logs::LogGroup',LogGroupName='/aws/ecs')
    policy=target('policy','AWS::Logs::AccountPolicy',PolicyType='TRANSFORMER_POLICY')
    if change=='other-region':policy.scope.region='us-west-2'
    if change=='other-account':policy.scope.account='222222222222'
    if change=='wrong-type':policy.fields[0].selected().value='FIELD_INDEX_POLICY'
    if change=='unknown-account':
        for r in [main,group,policy]:r.scope.account='unknown'
    if change=='unknown-region':
        for r in [main,group,policy]:r.scope.region='unknown'
    data=linked_design(main,[group,policy],[('LogGroupName','group')])
    if change=='conditional-group':data.relations[0].condition='optional'
    assert run_resource_checks(data,main)[0]['verdict']=='NEEDS_REVIEW'
