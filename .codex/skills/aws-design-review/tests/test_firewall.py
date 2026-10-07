from pathlib import Path
import pytest
from aws_design_sheet.checks.networkfirewall.firewall import evaluate_networkfirewall_firewall
from aws_design_sheet.checks.pinpoint.campaign_numeric_bounds import evaluate_pinpoint_campaign_numeric_bounds
from aws_design_sheet.checks.pipes.capacity_base_count import evaluate_pipes_capacity_base_count
from aws_design_sheet.checks.registry import combine
firewall_checks = combine(evaluate_networkfirewall_firewall, evaluate_pinpoint_campaign_numeric_bounds, evaluate_pipes_capacity_base_count)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,rule,**props):
    r=target('subject','AWS::'+kind,**props)
    return [x for x in firewall_checks(linked_design(r),r) if x['rule_id']==rule]


@pytest.mark.parametrize('policy',[False,True])
@pytest.mark.parametrize('actions,definitions,expected',[
    (['aws:pass'],[],'PASS'),(['aws:pass','metric'],[{'ActionName':'metric'}],'PASS'),
    (['aws:pass','missing'],[],'FAIL'),(['aws:pass','metric'],UNKNOWN,'NEEDS_REVIEW'),
    (['aws:pass','metric'],[{'ActionName':'metric'},UNKNOWN],'PASS'),
    (['aws:pass','aws:drop'],UNKNOWN,'FAIL'),([],[],'FAIL'),(['metric'],[{'ActionName':'metric'}],'FAIL'),
    (['aws:pass',UNKNOWN],[],'NEEDS_REVIEW'),([UNKNOWN],[],'NEEDS_REVIEW'),
    (['aws:pass','aws:pass'],[],'NEEDS_REVIEW'),(UNKNOWN,[],'NEEDS_REVIEW')])
def test_actions(policy,actions,definitions,expected):
    if policy:
        rows=check('NetworkFirewall::FirewallPolicy','NETWORKFIREWALL_POLICY_ACTIONS',FirewallPolicy={'StatelessCustomActions':definitions,'StatelessDefaultActions':actions,'StatelessFragmentDefaultActions':actions})
    else:
        rows=check('NetworkFirewall::RuleGroup','NETWORKFIREWALL_RULE_ACTIONS',RuleGroup={'RulesSource':{'StatelessRulesAndCustomActions':{'CustomActions':definitions,'StatelessRules':[{'RuleDefinition':{'Actions':actions}}]}}})
    assert rows and all(x['verdict']==expected for x in rows)


@pytest.mark.parametrize('flags,masks,expected',[
    (['SYN'],['SYN','ACK'],'PASS'),(['SYN'],['ACK'],'FAIL'),(['SYN'],['SYN',UNKNOWN],'PASS'),
    (['SYN'],[UNKNOWN],'NEEDS_REVIEW'),([UNKNOWN],['SYN'],'NEEDS_REVIEW'),
    (['SYN'],[],'NEEDS_REVIEW'),(['SYN'],None,'NEEDS_REVIEW')])
def test_masks(flags,masks,expected):
    item={'Flags':flags}
    if masks is not None:item['Masks']=masks
    props={'RulesSource':{'StatelessRulesAndCustomActions':{'StatelessRules':[{'RuleDefinition':{'MatchAttributes':{'TCPFlags':[item]}}}]}}}
    assert check('NetworkFirewall::RuleGroup','NETWORKFIREWALL_TCP_MASKS',RuleGroup=props)[0]['verdict']==expected


@pytest.mark.parametrize('options,expected',[
    ([[{'Keyword':'sid','Settings':['1']}],[{'Keyword':'sid','Settings':['2']}]],'PASS'),
    ([[{'Keyword':'sid','Settings':['001']}],[{'Keyword':'sid','Settings':['1']}]],'FAIL'),
    ([[{'Keyword':'msg','Settings':['x']}]],'FAIL'),([[]],'FAIL'),([UNKNOWN],'NEEDS_REVIEW'),
    ([[{'Keyword':'sid','Settings':[UNKNOWN]}]],'NEEDS_REVIEW'),
    ([[{'Keyword':'sid:1'}]],'NEEDS_REVIEW'),
    ([[{'Keyword':'sid','Settings':['1']},{'Keyword':'sid','Settings':['2']}]],'NEEDS_REVIEW')])
def test_structured_sid(options,expected):
    assert check('NetworkFirewall::RuleGroup','NETWORKFIREWALL_STRUCTURED_SID',RuleGroup={'RulesSource':{'StatefulRules':[{'RuleOptions':x} for x in options]}})[0]['verdict']==expected


@pytest.mark.parametrize('key,valid,bad',[
    ('Priority',5,6),('Limits/Daily',100,101),('Limits/Total',100,101),
    ('Limits/MaximumDuration',60,59),('Limits/MessagesPerSecond',20000,20001)])
@pytest.mark.parametrize('mode',['valid','bad','unknown','bool'])
def test_campaign_bounds(key,valid,bad,mode):
    n={'valid':valid,'bad':bad,'unknown':UNKNOWN,'bool':True}[mode]
    props={'Limits':{key.split('/')[1]:n}} if '/' in key else {key:n}
    expected='PASS' if mode=='valid' else 'FAIL' if mode=='bad' else 'NEEDS_REVIEW'
    assert check('Pinpoint::Campaign','PINPOINT_CAMPAIGN_NUMERIC_BOUNDS',**props)[0]['verdict']==expected


@pytest.mark.parametrize('strategy,expected',[
    ([{'CapacityProvider':'a','Base':0},{'CapacityProvider':'b','Weight':1}],'PASS'),
    ([{'CapacityProvider':'a','Base':0},{'CapacityProvider':'b','Base':0}],'FAIL'),
    ([{'CapacityProvider':'a','Base':1},{'CapacityProvider':'a','Base':2}],'NEEDS_REVIEW'),
    ([{'CapacityProvider':'a','Base':1},UNKNOWN],'NEEDS_REVIEW'),
    ([{'CapacityProvider':'a','Base':1},{'CapacityProvider':'b','Base':2},UNKNOWN],'FAIL'),
    ([{'CapacityProvider':'a','Base':True}],'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_capacity_base(strategy,expected):
    assert check('Pipes::Pipe','PIPES_CAPACITY_BASE_COUNT',TargetParameters={'EcsTaskParameters':{'CapacityProviderStrategy':strategy}})[0]['verdict']==expected


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::NetworkFirewall::FirewallPolicy',FirewallPolicy={'StatelessDefaultActions':['aws:pass','aws:drop']})
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    row=next(x for x in result['results'] if x['rule_id']=='NETWORKFIREWALL_POLICY_ACTIONS')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
