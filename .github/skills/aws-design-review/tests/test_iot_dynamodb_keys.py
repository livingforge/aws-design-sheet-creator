import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.iot.dynamodb_keys import evaluate_iot_dynamodb_keys
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(sort=True,error=False):
    action={'HashKeyField':'pk','HashKeyValue':'${topic()}'}
    if sort:action.update(RangeKeyField='sk',RangeKeyValue='${timestamp()}')
    payload={'ErrorAction':{'DynamoDB':action}} if error else {'Actions':[{'DynamoDB':action}]}
    r=target('rule','AWS::IoT::TopicRule',TopicRulePayload=payload)
    schema=[{'KeyType':'HASH','AttributeName':'pk'}]
    if sort:schema.append({'KeyType':'RANGE','AttributeName':'sk'})
    table=target('table','AWS::DynamoDB::Table',TableName='events',KeySchema=schema)
    path='TopicRulePayload/'+('ErrorAction' if error else 'Actions/0')+'/DynamoDB'
    d=linked_design(r,[table]);link(d,r,path+'/TableName',table)
    return d,r,table,action


@pytest.mark.parametrize('sort',[False,True])
@pytest.mark.parametrize('error',[False,True])
def test_primary_key_names(sort,error):
    d,r,*_=fixture(sort,error)
    assert evaluate_iot_dynamodb_keys(d,r)[0]['verdict']=='PASS'


@pytest.mark.parametrize('mode,expected',[
    ('hash_mismatch','FAIL'),('range_mismatch','FAIL'),('missing_range','FAIL'),
    ('unknown_hash','NEEDS_REVIEW'),('dynamic_range','NEEDS_REVIEW'),
    ('table_match','PASS'),('table_mismatch','NEEDS_REVIEW'),('dynamic_table','NEEDS_REVIEW'),
    ('unknown_schema','NEEDS_REVIEW'),('duplicate_key','NEEDS_REVIEW'),
    ('only_range','NEEDS_REVIEW'),('conditional','NEEDS_REVIEW'),
    ('scope','NEEDS_REVIEW'),('template','NEEDS_REVIEW'),
    ('no_reference','NEEDS_REVIEW'),('unknown_parent','NEEDS_REVIEW')])
def test_names_and_ambiguous_references(mode,expected):
    d,r,t,a=fixture()
    if mode=='hash_mismatch':a['HashKeyField']='wrong'
    if mode=='range_mismatch':a['RangeKeyField']='wrong'
    if mode=='missing_range':a.pop('RangeKeyField')
    if mode=='unknown_hash':a['HashKeyField']=UNKNOWN
    if mode=='dynamic_range':a['RangeKeyField']='${topic(2)}'
    if mode=='table_match':a['TableName']='events'
    if mode=='table_mismatch':a['TableName']='other'
    if mode=='dynamic_table':a['TableName']='${topic(2)}'
    if mode=='unknown_schema':t.fields[1].candidates[0].value=UNKNOWN
    if mode=='duplicate_key':t.fields[1].candidates[0].value[1]['KeyType']='HASH'
    if mode=='only_range':t.fields[1].candidates[0].value.pop(0)
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':t.scope.region='us-east-1'
    if mode=='template':t.template=TemplateContext(state='UNRESOLVED')
    if mode=='no_reference':d.relations.clear()
    if mode=='unknown_parent':r.fields[0].candidates[0].value=UNKNOWN
    assert evaluate_iot_dynamodb_keys(d,r)[0]['verdict']==expected


def test_secondary_index_does_not_replace_primary_key():
    d,r,t,a=fixture();a['HashKeyField']='gsi_pk'
    t.fields+=target('dummy',t.type,GlobalSecondaryIndexes=[{'IndexName':'gsi','KeySchema':[{'KeyType':'HASH','AttributeName':'gsi_pk'}]}]).fields
    assert evaluate_iot_dynamodb_keys(d,r)[0]['verdict']=='FAIL'


def test_extra_range_is_held_without_assuming_rejection():
    d,r,t,a=fixture(sort=False);a['RangeKeyField']='extra'
    assert evaluate_iot_dynamodb_keys(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='IOT_DYNAMODB_ACTION_KEY_NAMES' and f['verdict']=='PASS' for f in results)
