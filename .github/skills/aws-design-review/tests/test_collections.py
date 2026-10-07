import pytest
from aws_design_sheet.checks.appstream.stack_and_fleet_association import evaluate_appstream_stack_and_fleet_association
from aws_design_sheet.checks.applicationautoscaling.action_names_and_metric_ids import evaluate_applicationautoscaling_action_names_and_metric_ids
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from aws_design_sheet.checks.registry import combine
collections_checks=combine(evaluate_appstream_stack_and_fleet_association,evaluate_applicationautoscaling_action_names_and_metric_ids)


@pytest.mark.parametrize('kind,expected',[('ELASTIC','PASS'),('ALWAYS_ON','FAIL'),('ON_DEMAND','FAIL'),('future','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_fleet_type(kind,expected):
    r=target('association','AWS::AppStream::ApplicationFleetAssociation',FleetName='fleet')
    fleet=target('fleet','AWS::AppStream::Fleet',FleetType=kind)
    assert collections_checks(linked_design(r,[fleet],[('FleetName','fleet')]),r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['external','cross_scope','conditional','ambiguous'])
def test_unresolved_fleet(mode):
    r=target('association','AWS::AppStream::ApplicationFleetAssociation',FleetName='fleet')
    fleet=target('fleet','AWS::AppStream::Fleet',FleetType='ALWAYS_ON')
    d=linked_design(r,[fleet],[] if mode=='external' else [('FleetName','fleet')])
    if mode=='cross_scope':fleet.scope.region='eu-west-1'
    if mode=='conditional':d.relations[0].condition='flag'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'second'}))
    assert collections_checks(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('settings,expected',[
    ([('COMPUTER_INPUT','ENABLED'),('COMPUTER_VISION','ENABLED')],'PASS'),
    ([('COMPUTER_INPUT','ENABLED'),('COMPUTER_VISION','DISABLED')],'FAIL'),
    ([('COMPUTER_INPUT','ENABLED')],'FAIL'),([('COMPUTER_INPUT','DISABLED')],'PASS'),
    ([('COMPUTER_INPUT','ENABLED'),('COMPUTER_VISION',UNKNOWN)],'NEEDS_REVIEW'),
    ([('COMPUTER_INPUT','ENABLED'),('COMPUTER_VISION','ENABLED'),('COMPUTER_VISION','DISABLED')],'NEEDS_REVIEW'),
    ([(UNKNOWN,'ENABLED')],'NEEDS_REVIEW')])
def test_agent_settings(settings,expected):
    r=target('stack','AWS::AppStream::Stack',AgentAccessConfig={'Settings':[{'AgentAction':a,'Permission':p} for a,p in settings]})
    assert collections_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('metric',[False,True])
@pytest.mark.parametrize('names,expected',[(['a','b'],'PASS'),(['a','a'],'FAIL'),(['a',UNKNOWN],'NEEDS_REVIEW'),(['a','a',UNKNOWN],'FAIL'),([], 'PASS')])
def test_scaling_unique(metric,names,expected):
    if metric:
        kind='ScalingPolicy'; props={'TargetTrackingScalingPolicyConfiguration':{'CustomizedMetricSpecification':{'Metrics':[{'Id':n} for n in names]}}}
    else:
        kind='ScalableTarget'; props={'ScheduledActions':[{'ScheduledActionName':n} for n in names]}
    r=target('scaling','AWS::ApplicationAutoScaling::'+kind,**props)
    assert collections_checks(linked_design(r),r)[0]['verdict']==expected


def test_checker_registers_new_checks():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('association','AWS::AppStream::ApplicationFleetAssociation',FleetName='fleet')
    fleet=target('fleet','AWS::AppStream::Fleet',FleetType='ALWAYS_ON')
    d=linked_design(r,[fleet],[('FleetName','fleet')])
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)
    findings=result['results']
    assert any(f['rule_id']=='APPSTREAM_ELASTIC_ASSOCIATION' and f['verdict']=='FAIL' for f in findings)
