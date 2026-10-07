import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.iotevents.literal_expressions import evaluate_iotevents_literal_expressions
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def action_at(suffix,v):
    action={};node=action
    parts=suffix.split('/')
    for key in parts[:-1]:node=node.setdefault(key,{})
    node[parts[-1]]=v
    return action


def model(alarm,action,section='OnEnter',events='Events'):
    return target('main','AWS::IoTEvents::AlarmModel',AlarmEventActions={'AlarmActions':[action]}) if alarm else target('main','AWS::IoTEvents::DetectorModel',DetectorModelDefinition={'States':[{section:{events:[{'Actions':[action]}]}}]})


@pytest.mark.parametrize('alarm',[True,False])
@pytest.mark.parametrize('suffix,allowed',[
    ('DynamoDB/HashKeyType','STRING'),('DynamoDB/RangeKeyType','NUMBER'),('DynamoDB/Operation','DELETE'),
    ('IotSiteWise/PropertyValue/Quality','UNCERTAIN'),('IotSiteWise/PropertyValue/Value/BooleanValue','FALSE'),
])
@pytest.mark.parametrize('mode',['literal','invalid_literal','variable','concatenation','unquoted'])
def test_enum_literals(alarm,suffix,allowed,mode):
    raw={'literal':"'"+allowed+"'",'invalid_literal':"'WRONG'",'variable':'$variable.value','concatenation':"'"+allowed+"' + ''",'unquoted':allowed}[mode]
    r=model(alarm,action_at(suffix,raw))
    found=evaluate_iotevents_literal_expressions(linked_design(r),r)
    assert len(found)==1
    assert found[0]['verdict']==('PASS' if mode=='literal' else 'FAIL' if mode=='invalid_literal' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,expected',[
    ('60','PASS'),('60.9','PASS'),('31622400','PASS'),('0','FAIL'),('-1','FAIL'),('.9','FAIL'),
    ('31622401','FAIL'),('1','NEEDS_REVIEW'),('59.9','NEEDS_REVIEW'),('31622400.9','NEEDS_REVIEW'),
    ('1e2','NEEDS_REVIEW'),('60 + 1','NEEDS_REVIEW'),("'60'",'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),
])
def test_timer_bounds_and_rounding_uncertainty(raw,expected):
    r=model(False,{'SetTimer':{'DurationExpression':raw}})
    assert evaluate_iotevents_literal_expressions(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('section,events',[('OnEnter','Events'),('OnExit','Events'),('OnInput','Events'),('OnInput','TransitionEvents')])
def test_detector_action_locations(section,events):
    r=model(False,{'DynamoDB':{'Operation':"'WRONG'"}},section,events)
    assert evaluate_iotevents_literal_expressions(linked_design(r),r)[0]['verdict']=='FAIL'


@pytest.mark.parametrize('mode',['template','substitution','escaped','unknown_actions','unknown_states'])
def test_unsupported_expression_forms(mode):
    raw="'${$variable.value}'" if mode=='substitution' else "'STR\\ING'" if mode=='escaped' else "'STRING'"
    r=model(False,{'DynamoDB':{'HashKeyType':raw}})
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='unknown_actions':r.fields[0].candidates[0].value['States'][0]['OnEnter']['Events'][0]['Actions']=UNKNOWN
    if mode=='unknown_states':r.fields[0].candidates[0].value['States']=UNKNOWN
    assert all(f['verdict']=='NEEDS_REVIEW' for f in evaluate_iotevents_literal_expressions(linked_design(r),r))


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1];r=model(True,{'DynamoDB':{'Operation':"'UPSERT'"}})
    assert any(f['rule_id']=='IOTEVENTS_ALARM_LITERAL_VALUES' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
