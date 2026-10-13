"""Stateful rule-group order compatibility with explicitly linked policies."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'NETWORK_FIREWALL_STATEFUL_ORDER_COMPATIBILITY':[CF+'aws-properties-networkfirewall-rulegroup-rulegroup.html',CF+'aws-properties-networkfirewall-rulegroup-statefulruleoptions.html',CF+'aws-properties-networkfirewall-firewallpolicy-statefulengineoptions.html','https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html']}


def mode(ctx,r,path):
    raw=value(ctx,r,path)
    if raw is ABSENT:return 'DEFAULT_ACTION_ORDER'
    return raw if raw in ('DEFAULT_ACTION_ORDER','STRICT_ORDER') else None


def reference(ctx,policy,path):
    if not resolved(policy):return None
    group=linked(ctx,policy,path,'AWS::NetworkFirewall::RuleGroup')
    if not resolved(group):return None
    raw=read(ctx,policy,path)
    if raw is ABSENT:return group
    match=re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):network-firewall:([a-z0-9-]+):([0-9]{12}):stateful-rulegroup/([a-zA-Z0-9-]+)',raw) if literal(raw) else None
    if match and (match[2],match[3],match[4])==(group.scope.region,group.scope.account,value(ctx,group,'/properties/RuleGroupName')):return group
    return None


def compatibility(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    typ=value(ctx,r,'/properties/Type')
    if typ=='STATELESS':return 'NOT_APPLICABLE'
    if typ!='STATEFUL':return 'NEEDS_REVIEW'
    own=mode(ctx,r,'/properties/RuleGroup/StatefulRuleOptions/RuleOrder')
    if own is None:return 'NEEDS_REVIEW'
    seen=False;pending=False
    for policy in ctx.design.resources:
        if policy.type!='AWS::NetworkFirewall::FirewallPolicy':continue
        refs=[ref for ref in ctx.design.relations if ref.source_resource_id==policy.id and ref.target_resource_id==r.id and re.fullmatch(r'/properties/FirewallPolicy/StatefulRuleGroupReferences/[0-9]+/ResourceArn',ref.source_path)]
        for ref in refs:
            if reference(ctx,policy,ref.source_path) is not r:pending=True;continue
            other=mode(ctx,policy,'/properties/FirewallPolicy/StatefulEngineOptions/RuleOrder')
            if other is None:pending=True
            elif own!=other:return 'FAIL'
            else:seen=True
    return 'PASS' if seen and not pending else 'NEEDS_REVIEW'


@resource_check('AWS::NetworkFirewall::RuleGroup')
def evaluate_networkfirewall_firewall_rule_order(design,resource):
    if resource.type!='AWS::NetworkFirewall::RuleGroup':return []
    ctx=_Context(design,resource)
    f=ctx.finding('NETWORK_FIREWALL_STATEFUL_ORDER_COMPATIBILITY','/properties/RuleGroup/StatefulRuleOptions/RuleOrder',compatibility(ctx,resource),'Stateful rule-group evaluation order must match each explicitly linked firewall policy. Omitted rule order uses documented DEFAULT_ACTION_ORDER. Unknown policies, conditional references, conflicting ARN identities and external consumers remain reviewable. PASS concerns declared order compatibility only, not Suricata content or live firewall behavior.')
    f['source_checked_at']='2026-10-04';return [f]
