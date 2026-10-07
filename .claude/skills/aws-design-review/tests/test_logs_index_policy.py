import json
import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('body,minimum,exclusive',[
    ({},'FAIL','PASS'),({'Fields':[],'FieldsV2':{}},'FAIL','PASS'),
    ({'Fields':['id']},'PASS','PASS'),({'FieldsV2':{'id':{'type':'FACET'}}},'PASS','PASS'),
    ({'Fields':['id'],'FieldsV2':{'id':{'type':'FIELD_INDEX'}}},'PASS','FAIL'),
    ({'Fields':['ID'],'FieldsV2':{'id':{'type':'FIELD_INDEX'}}},'PASS','PASS'),
    ({'Fields':[UNKNOWN]},'NEEDS_REVIEW','NEEDS_REVIEW'),
    ({'FieldsV3':['id']},'NEEDS_REVIEW','NEEDS_REVIEW'),
    ([], 'NEEDS_REVIEW','NEEDS_REVIEW'),
    ({'FieldsV2':UNKNOWN},'NEEDS_REVIEW','NEEDS_REVIEW'),
])
def test_fields_and_v2(body,minimum,exclusive):
    main=target('policy','AWS::Logs::AccountPolicy',PolicyType='FIELD_INDEX_POLICY',PolicyDocument=json.dumps(body))
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
    assert rows['LOGS_INDEX_POLICY_MINIMUM']==minimum
    assert rows['LOGS_INDEX_POLICY_FIELDS_EXCLUSIVE']==exclusive


@pytest.mark.parametrize('kind,expected',[('FIELD_INDEX','PASS'),('FACET','PASS'),('OTHER','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_fields_v2_type(kind,expected):
    main=target('policy','AWS::Logs::AccountPolicy',PolicyType='FIELD_INDEX_POLICY',PolicyDocument=json.dumps({'FieldsV2':{'id':{'type':kind}}}))
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
    assert rows['LOGS_INDEX_POLICY_FIELD_TYPE']==expected


def test_duplicate_document_keys_are_ambiguous():
    main=target('policy','AWS::Logs::AccountPolicy',PolicyType='FIELD_INDEX_POLICY',PolicyDocument='{"Fields": [], "Fields": ["id"]}')
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
    assert rows['LOGS_INDEX_POLICY_MINIMUM']=='NEEDS_REVIEW'


@pytest.mark.parametrize('other_name,scope,expected',[
    ('second','same','FAIL'),('first','same','NEEDS_REVIEW'),
    (UNKNOWN,'same','NEEDS_REVIEW'),('second','other','NEEDS_REVIEW'),
    ('second','unknown','NEEDS_REVIEW')])
def test_integration_singleton(other_name,scope,expected):
    main=target('one','AWS::Logs::Integration',IntegrationName='first')
    other=target('two','AWS::Logs::Integration',IntegrationName=other_name)
    if scope=='other':other.scope.region='us-west-2'
    if scope=='unknown':main.scope.account=other.scope.account='unknown'
    assert run_resource_checks(linked_design(main,[other]),main)[0]['verdict']==expected
