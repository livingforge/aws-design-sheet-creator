from pathlib import Path
import pytest
from aws_design_sheet.checks.common.decimal_places import decimal_places
from aws_design_sheet.checks.greengrassv2.job_decimal_places import evaluate_greengrassv2_job_decimal_places
from aws_design_sheet.checks.guardduty.malware_and_publishing import evaluate_guardduty_malware_and_publishing
from aws_design_sheet.checks.gamelift.matchmaking_ruleset_region import evaluate_gamelift_matchmaking_ruleset_region
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
guard_inputs_checks = combine(evaluate_greengrassv2_job_decimal_places, evaluate_guardduty_malware_and_publishing, evaluate_gamelift_matchmaking_ruleset_region)


@pytest.mark.parametrize('raw,places,expected',[
    (10,2,'PASS'),(10.9,2,'PASS'),(10.99,2,'PASS'),(10.999,2,'FAIL'),
    (1.5,1,'PASS'),(1.55,1,'FAIL'),(1.0,1,'PASS'),(0.01,2,'PASS'),
    (1e-3,2,'FAIL'),(0.0,1,'PASS'),(1e12,1,'PASS'),(1e13,1,'NEEDS_REVIEW'),
    (True,1,'NEEDS_REVIEW'),('1.5',1,'NEEDS_REVIEW'),(UNKNOWN,1,'NEEDS_REVIEW'),
    (float('nan'),1,'NEEDS_REVIEW'),(float('inf'),1,'NEEDS_REVIEW'),
])
def test_decimals(raw,places,expected):
    assert decimal_places(raw,places)==expected


@pytest.mark.parametrize('mode',['valid','threshold','factor','unknown_list','unknown_parent','unknown_item','omitted'])
def test_job(mode):
    config={'AbortConfig':{'CriteriaList':[{'ThresholdPercentage':10.999 if mode=='threshold' else 10.99}]},'JobExecutionsRolloutConfig':{'ExponentialRate':{'IncrementFactor':1.55 if mode=='factor' else 1.5}}}
    if mode=='unknown_list':config['AbortConfig']['CriteriaList']=UNKNOWN
    if mode=='unknown_item':config['AbortConfig']['CriteriaList']=[UNKNOWN]
    if mode=='unknown_parent':config=UNKNOWN
    r=target('main','AWS::GreengrassV2::Deployment',**({} if mode=='omitted' else {'IotJobConfiguration':config}))
    results=guard_inputs_checks(linked_design(r),r)
    if mode=='omitted':assert not results
    elif mode in ('threshold','factor'):assert sum(f['verdict']=='FAIL' for f in results)==1
    elif mode.startswith('unknown'):assert any(f['verdict']=='NEEDS_REVIEW' for f in results) and not any(f['verdict']=='FAIL' for f in results)
    else:assert len(results)==2 and all(f['verdict']=='PASS' for f in results)


@pytest.mark.parametrize('mode',['valid','lowercase','unsupported','unknown','dynamic','omitted','ancestor'])
def test_enums(mode):
    raw='ENABLED'
    if mode=='lowercase':raw=raw.lower()
    if mode=='unsupported':raw='OTHER'
    if mode=='unknown':raw=UNKNOWN
    if mode=='dynamic':raw={'Ref':'Value'}
    props={'Actions':UNKNOWN if mode=='ancestor' else {'Tagging':{'Status':raw}}}
    r=target('main','AWS::GuardDuty::MalwareProtectionPlan',**({} if mode=='omitted' else props))
    results=guard_inputs_checks(linked_design(r),r)
    if mode=='omitted':assert not results
    else:assert results[0]['verdict']==('PASS' if mode=='valid' else 'FAIL' if mode in ('lowercase','unsupported') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['same','region','account','environment','name','unknown','arn','conditional','ambiguous','missing','wrong_type','template','target_template','scope'])
def test_ruleset(mode):
    from aws_design_sheet.models import TemplateContext
    r=target('main','AWS::GameLift::MatchmakingConfiguration',RuleSetName=UNKNOWN if mode=='unknown' else 'arn:aws:gamelift:us-east-1:111111111111:matchmakingruleset/rules' if mode=='arn' else 'rules')
    other=target('rules','AWS::GameLift::MatchmakingRuleSet',Name='other' if mode=='name' else 'rules')
    d=linked_design(r,[other],[] if mode=='missing' else [('RuleSetName','rules')])
    if mode in ('region','account','environment'):setattr(other.scope,mode,{'region':'us-east-1','account':'222222222222','environment':'other'}[mode])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='wrong_type':other.type='AWS::SNS::Topic'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='target_template':other.template=TemplateContext(state='UNRESOLVED')
    if mode=='scope':other.scope.region='unknown'
    assert guard_inputs_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='region' else 'NEEDS_REVIEW')


def test_checker_malware_tagging():
    r=target('main','AWS::GuardDuty::MalwareProtectionPlan',Actions={'Tagging':{'Status':'OTHER'}})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='GUARDDUTY_MALWARE_TAGGING_STATUS' and f['verdict']=='FAIL' for f in results)
