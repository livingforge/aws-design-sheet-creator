from pathlib import Path
import pytest
from aws_design_sheet.checks.config.daily_overrides import DAILY_FORBIDDEN, evaluate_config_daily_overrides
from aws_design_sheet.checks.cognito.identity_pool_role_attachment import evaluate_cognito_identity_pool_role_attachment
from aws_design_sheet.checks.connect.forms import evaluate_connect_forms
from aws_design_sheet.checks.registry import combine
forms_checks = combine(evaluate_cognito_identity_pool_role_attachment, evaluate_config_daily_overrides, evaluate_connect_forms)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,rule=None,**props):
    r=target('subject',kind,**props)
    return [x for x in forms_checks(linked_design(r),r) if rule is None or x['rule_id']==rule]


@pytest.mark.parametrize('roles,expected',[({'authenticated':'arn'},'PASS'),({'unauthenticated':UNKNOWN},'PASS'),
    ({'admin':'arn'},'FAIL'),({'${role}':'arn'},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_role_keys(roles,expected):
    assert check('AWS::Cognito::IdentityPoolRoleAttachment',Roles=roles)[0]['verdict']==expected


@pytest.mark.parametrize('mapping,expected',[
    ({'Type':'Token','AmbiguousRoleResolution':'Deny'},'PASS'),({'Type':'Token'},'FAIL'),
    ({'Type':'Rules','AmbiguousRoleResolution':'Deny'},'FAIL'),
    ({'Type':'Rules','AmbiguousRoleResolution':'Deny','RulesConfiguration':{}},'FAIL'),
    ({'Type':'Token','AmbiguousRoleResolution':UNKNOWN},'NEEDS_REVIEW'),
    ({'Type':UNKNOWN},'NEEDS_REVIEW')])
def test_mapping_dependencies(mapping,expected):
    assert check('AWS::Cognito::IdentityPoolRoleAttachment',RoleMappings={'provider':mapping})[0]['verdict']==expected


@pytest.mark.parametrize('count,match,expected',[(25,'Equals','PASS'),(26,'Equals','FAIL'),(1,'Contains','PASS'),
    (1,'StartsWith','PASS'),(1,'NotEqual','PASS'),(1,'NotEquals','FAIL'),(1,UNKNOWN,'NEEDS_REVIEW')])
def test_mapping_rules(count,match,expected):
    mapping={'Type':'Rules','AmbiguousRoleResolution':'Deny','RulesConfiguration':{'Rules':[{'MatchType':match} for _ in range(count)]}}
    assert check('AWS::Cognito::IdentityPoolRoleAttachment',RoleMappings={'provider':mapping})[0]['verdict']==expected


def test_mapping_escaped_and_unknown_rule():
    assert check('AWS::Cognito::IdentityPoolRoleAttachment',RoleMappings={'issuer/pool':{'Type':'Token'}})[0]['verdict']=='NEEDS_REVIEW'
    mapping={'Type':'Rules','AmbiguousRoleResolution':'Deny','RulesConfiguration':{'Rules':[{'MatchType':'Equals'}]*25+[UNKNOWN]}}
    assert check('AWS::Cognito::IdentityPoolRoleAttachment',RoleMappings={'provider':mapping})[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('kind',sorted(DAILY_FORBIDDEN))
def test_daily_forbidden(kind):
    assert check('AWS::Config::ConfigurationRecorder',RecordingMode={'RecordingModeOverrides':[
        {'RecordingFrequency':'DAILY','ResourceTypes':[kind]}]})[0]['verdict']=='FAIL'


@pytest.mark.parametrize('frequency,types,expected',[('DAILY',['AWS::S3::Bucket'],'PASS'),('DAILY',[UNKNOWN],'NEEDS_REVIEW'),
    (UNKNOWN,['AWS::Config::ResourceCompliance'],'NEEDS_REVIEW')])
def test_daily_uncertainty(frequency,types,expected):
    assert check('AWS::Config::ConfigurationRecorder',RecordingMode={'RecordingModeOverrides':[
        {'RecordingFrequency':frequency,'ResourceTypes':types}]})[0]['verdict']==expected


def test_daily_default_all_supported_not_rejected():
    rows=check('AWS::Config::ConfigurationRecorder',RecordingMode={'RecordingFrequency':'DAILY'},RecordingGroup={'AllSupported':True})
    assert rows[0]['verdict']=='NEEDS_REVIEW'


def question(ref,options=None):
    node={'RefId':ref}
    if options is not None:node['QuestionTypeProperties']={'SingleSelect':{'Options':[{'RefId':x} for x in options]}}
    return {'Question':node}


def section(ref,items):return {'Section':{'RefId':ref,'Items':items}}


@pytest.mark.parametrize('count,expected',[(99,'PASS'),(100,'PASS'),(101,'FAIL')])
@pytest.mark.parametrize('sections',[False,True])
def test_form_counts(count,expected,sections):
    items=[section('s'+str(i),[]) for i in range(count)] if sections else [section('s',[question('q'+str(i)) for i in range(count)])]
    assert check('AWS::Connect::EvaluationForm','CONNECT_FORM_COUNTS',Items=items)[0]['verdict']==expected


def test_form_nested_and_unknown():
    items=[section('root',[section('sub',[question('q'+str(i)) for i in range(100)]),question('extra')])]
    assert check('AWS::Connect::EvaluationForm','CONNECT_FORM_COUNTS',Items=items)[0]['verdict']=='FAIL'
    assert check('AWS::Connect::EvaluationForm','CONNECT_FORM_COUNTS',Items=[section('s',UNKNOWN)])[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('items,expected',[
    ([section('s',[question('q')])],'PASS'),([section('s',[question('s')])],'FAIL'),
    ([section('s',[question('q')]),section('t',[question('q')])],'FAIL'),
    ([section('s',[question(UNKNOWN)])],'NEEDS_REVIEW')])
def test_form_ids(items,expected):
    assert check('AWS::Connect::EvaluationForm','CONNECT_FORM_IDS',Items=items)[-1]['verdict']==expected


def test_answer_ids_are_question_local():
    items=[section('s',[question('q1',['a','b']),question('q2',['a','b'])])]
    assert all(r['verdict']=='PASS' for r in check('AWS::Connect::EvaluationForm','CONNECT_FORM_IDS',Items=items))
    items=[section('s',[question('q1',['a','a'])])]
    assert check('AWS::Connect::EvaluationForm','CONNECT_FORM_IDS',Items=items)[0]['verdict']=='FAIL'


@pytest.mark.parametrize('types,expected',[(['NAME'],'PASS'),(['TEXT'],'FAIL'),(['TEXT',UNKNOWN],'NEEDS_REVIEW'),
    (['NAME',UNKNOWN],'PASS'),([],'FAIL')])
def test_task_name(types,expected):
    assert check('AWS::Connect::TaskTemplate',Fields=[{'Type':t} for t in types])[0]['verdict']==expected


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::Connect::TaskTemplate',Fields=[{'Type':'TEXT'}])
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    row=next(r for r in result['results'] if r['rule_id']=='CONNECT_TASK_NAME_FIELD')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
