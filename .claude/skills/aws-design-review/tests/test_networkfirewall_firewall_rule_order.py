import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.networkfirewall.firewall_rule_order import evaluate_networkfirewall_firewall_rule_order
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(group_order=None,policy_order=None):
    group={} if group_order is None else {'StatefulRuleOptions':{'RuleOrder':group_order}}
    policy={'StatefulRuleGroupReferences':[{}]}
    if policy_order is not None:policy['StatefulEngineOptions']={'RuleOrder':policy_order}
    r=target('group','AWS::NetworkFirewall::RuleGroup',Type='STATEFUL',RuleGroupName='rules',RuleGroup=group)
    p=target('policy','AWS::NetworkFirewall::FirewallPolicy',FirewallPolicy=policy)
    d=linked_design(r,[p]);link(d,p,'FirewallPolicy/StatefulRuleGroupReferences/0/ResourceArn',r)
    return d,r,p


@pytest.mark.parametrize('left',[None,'DEFAULT_ACTION_ORDER','STRICT_ORDER'])
@pytest.mark.parametrize('right',[None,'DEFAULT_ACTION_ORDER','STRICT_ORDER'])
def test_both_orders_and_documented_defaults(left,right):
    d,r,p=fixture(left,right)
    expected='PASS' if (left or 'DEFAULT_ACTION_ORDER')==(right or 'DEFAULT_ACTION_ORDER') else 'FAIL'
    assert evaluate_networkfirewall_firewall_rule_order(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('mode,expected',[
    ('unknown_group','NEEDS_REVIEW'),('unknown_policy','NEEDS_REVIEW'),
    ('conditional','NEEDS_REVIEW'),('scope','NEEDS_REVIEW'),('template','NEEDS_REVIEW'),
    ('no_consumer','NEEDS_REVIEW'),('matching_arn','PASS'),('wrong_arn','NEEDS_REVIEW'),
    ('stateless','NOT_APPLICABLE'),('unknown_type','NEEDS_REVIEW')])
def test_unknowns_and_reference_identity(mode,expected):
    d,r,p=fixture()
    if mode=='unknown_group':r.fields[-1].candidates[0].value=UNKNOWN
    if mode=='unknown_policy':p.fields[0].candidates[0].value['StatefulEngineOptions']=UNKNOWN
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':p.scope.region='us-east-1'
    if mode=='template':p.template=TemplateContext(state='UNRESOLVED')
    if mode=='no_consumer':d.resources.remove(p)
    if mode in ('matching_arn','wrong_arn'):
        p.fields[0].candidates[0].value['StatefulRuleGroupReferences'][0]['ResourceArn']='arn:aws:network-firewall:ap-northeast-1:111111111111:stateful-rulegroup/'+('rules' if mode=='matching_arn' else 'other')
    if mode=='stateless':r.fields[0].candidates[0].value='STATELESS'
    if mode=='unknown_type':r.fields[0].candidates[0].value=UNKNOWN
    assert evaluate_networkfirewall_firewall_rule_order(d,r)[0]['verdict']==expected


def test_every_declared_consumer_is_checked():
    d,r,p=fixture('STRICT_ORDER','STRICT_ORDER')
    other=target('other',p.type,FirewallPolicy={'StatefulRuleGroupReferences':[{}]})
    d.resources.append(other);link(d,other,'FirewallPolicy/StatefulRuleGroupReferences/0/ResourceArn',r)
    assert evaluate_networkfirewall_firewall_rule_order(d,r)[0]['verdict']=='FAIL'
    d.relations[-1].condition='Maybe'
    assert evaluate_networkfirewall_firewall_rule_order(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture('STRICT_ORDER','DEFAULT_ACTION_ORDER');root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='NETWORK_FIREWALL_STATEFUL_ORDER_COMPATIBILITY' and f['verdict']=='FAIL' for f in results)
