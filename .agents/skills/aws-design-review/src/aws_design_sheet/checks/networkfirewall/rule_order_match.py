"""Checks for AWS::NetworkFirewall::FirewallPolicy."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import expand
from ..common.scoped_resolution import resolved

SOURCES = {
    'NETWORKFIREWALL_RULE_ORDER_MATCH': ['https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html'],
}


def rule_order(ctx,resource,path):
    if not resolved(resource):return 'NEEDS_REVIEW'
    group=linked(ctx,resource,path,'AWS::NetworkFirewall::RuleGroup')
    if not resolved(group) or value(ctx,group,'/properties/Type')!='STATEFUL':return 'NEEDS_REVIEW'
    policy_order=value(ctx,resource,'/properties/FirewallPolicy/StatefulEngineOptions/RuleOrder')
    group_order=value(ctx,group,'/properties/RuleGroup/StatefulRuleOptions/RuleOrder')
    allowed=('DEFAULT_ACTION_ORDER','STRICT_ORDER')
    if policy_order not in allowed or group_order not in allowed:return 'NEEDS_REVIEW'
    return 'PASS' if policy_order==group_order else 'FAIL'


@resource_check('AWS::NetworkFirewall::FirewallPolicy')
def evaluate_networkfirewall_rule_order_match(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::NetworkFirewall::FirewallPolicy':
        for path in expand(ctx,resource,'/properties/FirewallPolicy/StatefulRuleGroupReferences/*/ResourceArn'):
            emit('NETWORKFIREWALL_RULE_ORDER_MATCH',path,rule_order(ctx,resource,path),'explicit policy and linked stateful group rule ordering must match; omitted defaults, unknown group types/options, managed/external groups, other engine settings and runtime traffic behavior remain held')
    return results
