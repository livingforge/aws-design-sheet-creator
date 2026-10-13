"""Checks for AWS::NetworkFirewall::FirewallPolicy, AWS::NetworkFirewall::RuleGroup."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from ..common.string_lists import strings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'NETWORKFIREWALL_POLICY_ACTIONS': [CF+'aws-properties-networkfirewall-firewallpolicy-firewallpolicy.html'],
    'NETWORKFIREWALL_RULE_ACTIONS': [CF+'aws-properties-networkfirewall-rulegroup-ruledefinition.html'],
    'NETWORKFIREWALL_TCP_MASKS': [CF+'aws-properties-networkfirewall-rulegroup-tcpflagfield.html'],
    'NETWORKFIREWALL_STRUCTURED_SID': [CF+'aws-properties-networkfirewall-rulegroup-ruleoption.html','https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html'],
}
STANDARD={'aws:pass','aws:drop','aws:forward_to_sfe'}


def actions(ctx,resource,path,definitions):
    names,pending=strings(ctx,resource,path)
    defined=value(ctx,resource,definitions);known=set();complete=defined is ABSENT or isinstance(defined,list)
    for i in range(len(defined)) if isinstance(defined,list) else ():
        name=value(ctx,resource,definitions+'/'+str(i)+'/ActionName')
        if literal(name):known.add(name)
        else:complete=False
    standard=[n for n in names if n in STANDARD];custom=set(names)-STANDARD
    invalid=len(set(standard))>1 or not standard and not pending or complete and bool(custom-known)
    pending|=len(standard)>1 or bool(custom-known) and not complete
    return 'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::NetworkFirewall::FirewallPolicy', 'AWS::NetworkFirewall::RuleGroup')
def evaluate_networkfirewall_firewall(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::NetworkFirewall::FirewallPolicy':
        base='/properties/FirewallPolicy'
        for key in ('StatelessDefaultActions','StatelessFragmentDefaultActions'):
            path=base+'/'+key
            if get(path) is not ABSENT:
                emit('NETWORKFIREWALL_POLICY_ACTIONS',path,actions(ctx,resource,path,base+'/StatelessCustomActions'),'requires one standard action and locally defined custom action names; duplicate same standard, unknown arrays and action compatibility remain under review')
    if resource.type=='AWS::NetworkFirewall::RuleGroup':
        base='/properties/RuleGroup/RulesSource/StatelessRulesAndCustomActions'
        for rule_path in expand(ctx,resource,base+'/StatelessRules/*/RuleDefinition'):
            path=rule_path+'/Actions'
            emit('NETWORKFIREWALL_RULE_ACTIONS',path,actions(ctx,resource,path,base+'/CustomActions'),'requires one standard action plus defined custom names; unknown arrays, duplicate same standard and action compatibility remain under review')
            for path in expand(ctx,resource,rule_path+'/MatchAttributes/TCPFlags/*'):
                flags,pending=strings(ctx,resource,path+'/Flags');masks,mask_pending=strings(ctx,resource,path+'/Masks')
                missing=set(flags)-set(masks)
                verdict='FAIL' if missing and not mask_pending else 'PASS' if not pending and not missing and get(path+'/Masks') is not ABSENT else 'NEEDS_REVIEW'
                # Empty Masks may mean no setting; preserve that ambiguity.
                if get(path+'/Masks')==[]:verdict='NEEDS_REVIEW'
                emit('NETWORKFIREWALL_TCP_MASKS',path,verdict,'explicit Flags must occur in explicit nonempty Masks; omitted/empty masks inspect all or need interpretation and are held; unknown values remain under review')
        path='/properties/RuleGroup/RulesSource/StatefulRules';raw=get(path)
        if raw is not ABSENT:
            pending=not isinstance(raw,list);invalid=False;seen=set()
            for i in range(len(raw)) if isinstance(raw,list) else ():
                p=path+'/'+str(i)+'/RuleOptions';options=get(p);local_pending=not isinstance(options,list);ids=[];has_sid=False
                for j in range(len(options)) if isinstance(options,list) else ():
                    option=p+'/'+str(j);keyword=get(option+'/Keyword')
                    if not literal(keyword) or ':' in keyword:local_pending=True;continue
                    if keyword!='sid':continue
                    has_sid=True;settings=get(option+'/Settings')
                    if isinstance(settings,list) and len(settings)==1:
                        n=get(option+'/Settings/0')
                        if isinstance(n,str) and re.fullmatch(r'[0-9]+',n):ids.append(n.lstrip('0') or '0')
                        else:local_pending=True
                    else:local_pending=True
                if not has_sid and not local_pending:invalid=True
                if len(ids)==1:
                    if ids[0] in seen:invalid=True
                    seen.add(ids[0])
                elif has_sid:local_pending=True
                pending|=local_pending
            emit('NETWORKFIREWALL_STRUCTURED_SID',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','structured stateful rules require sid and numeric IDs must be unique across rules; embedded keyword syntax, multiple sid options, unknown values and free-form rule strings remain under review')
    return results
