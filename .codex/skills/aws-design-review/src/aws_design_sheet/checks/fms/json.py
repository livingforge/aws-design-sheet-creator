"""Checks for AWS::FMS::Policy."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.strict_json import parse

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={rule:[CF+'aws-properties-fms-policy-securityservicepolicydata.html','https://docs.aws.amazon.com/fms/2018-01-01/APIReference/API_SecurityServicePolicyData.html'] for rule in ('FMS_DNS_RULE_PRIORITY','FMS_SHIELD_RESPONSE_ACTION','FMS_WAF_LOGGING_LIMITS')}
RULE_TYPES={'FMS_DNS_RULE_PRIORITY':'DNS_FIREWALL','FMS_SHIELD_RESPONSE_ACTION':'SHIELD_ADVANCED','FMS_WAF_LOGGING_LIMITS':'WAFV2'}


def priorities(node):
    seen=False;pending=False
    for key,low,high in [('preProcessRuleGroups',1,99),('postProcessRuleGroups',9901,10000)]:
        rows=node.get(key,[])
        if not isinstance(rows,list):pending=True;continue
        for row in rows:
            raw=row.get('priority') if isinstance(row,dict) else None
            if type(raw) is not int:pending=True
            elif not low<=raw<=high:return 'FAIL'
            else:seen=True
    return 'NEEDS_REVIEW' if pending else 'PASS' if seen else 'NOT_APPLICABLE'


def response_action(node):
    config=node.get('automaticResponseConfiguration',ABSENT)
    if config is ABSENT:return 'NOT_APPLICABLE'
    if not isinstance(config,dict):return 'NEEDS_REVIEW'
    status=config.get('automaticResponseStatus','IGNORED')
    if status in ('IGNORED','DISABLED'):return 'NOT_APPLICABLE'
    if status!='ENABLED':return 'NEEDS_REVIEW'
    action=config.get('automaticResponseAction',ABSENT)
    if action is ABSENT:return 'FAIL'
    if not literal(action):return 'NEEDS_REVIEW'
    return 'PASS' if action in ('BLOCK','COUNT') else 'FAIL'


def logging_limits(node):
    config=node.get('loggingConfiguration',ABSENT)
    if config is ABSENT:return 'NOT_APPLICABLE'
    if not isinstance(config,dict):return 'NEEDS_REVIEW'
    pending=False;seen=False
    for key,limit in [('logDestinationConfigs',1),('redactedFields',20)]:
        raw=config.get(key,ABSENT)
        if raw is ABSENT:continue
        if not isinstance(raw,list):pending=True
        elif len(raw)>limit:return 'FAIL'
        else:seen=True
    return 'NEEDS_REVIEW' if pending or not seen else 'PASS'


@resource_check('AWS::FMS::Policy')
def evaluate_fms_json(design,resource):
    if resource.type!='AWS::FMS::Policy':return []
    ctx=_Context(design,resource);base='/properties/SecurityServicePolicyData'
    kind=value(ctx,resource,base+'/Type');node=parse(value(ctx,resource,base+'/ManagedServiceData'))
    known_template=resource.template is None or resource.template.state.value=='KNOWN'
    results=[]
    for rule,fn in [('FMS_DNS_RULE_PRIORITY',priorities),('FMS_SHIELD_RESPONSE_ACTION',response_action),('FMS_WAF_LOGGING_LIMITS',logging_limits)]:
        if literal(kind) and kind!=RULE_TYPES[rule]:continue
        verdict=fn(node) if known_template and node is not None and kind==node.get('type')==RULE_TYPES[rule] else 'NEEDS_REVIEW'
        f=ctx.finding(rule,base+'/ManagedServiceData',verdict,'Inspect bounded literal JSON only: DNS priorities 1–99/9901–10000; Shield ENABLED requires BLOCK or COUNT; WAF logging has at most one destination and 20 redactions. Inactive Shield action is not prohibited by a required-only-when statement. Duplicates, dynamic content, unknown templates and type conflicts remain reviewable. Firewall deployment model and redaction type documentation discrepancies are separate; PASS is limited to these clauses.')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
