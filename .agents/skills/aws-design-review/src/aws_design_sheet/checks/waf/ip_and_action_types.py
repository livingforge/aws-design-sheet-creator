"""Checks for AWS::WAF::IPSet, AWS::WAF::WebACL."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'WAF_CLASSIC_IP_DESCRIPTOR_TYPE': [CF+'aws-properties-waf-ipset-ipsetdescriptor.html'],
    'WAF_CLASSIC_RULE_ACTION_TYPE': [CF+'aws-properties-waf-webacl-wafaction.html'],
}


@resource_check('AWS::WAF::IPSet','AWS::WAF::WebACL')
def evaluate_waf_ip_and_action_types(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    for kind,rule,pattern,allowed in (
        ('AWS::WAF::IPSet','WAF_CLASSIC_IP_DESCRIPTOR_TYPE','/properties/IPSetDescriptors/*/Type',('IPV4','IPV6')),
        ('AWS::WAF::WebACL','WAF_CLASSIC_RULE_ACTION_TYPE','/properties/Rules/*/Action/Type',('BLOCK','ALLOW','COUNT'))):
        if resource.type==kind:
            for path in expand(ctx,resource,pattern):
                raw=value(ctx,resource,path)
                emit(rule,path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','documented legacy literal value only; unknowns, CIDR/action context, default-action constraints and post-support service availability remain held; PASS does not imply resource can be created')
    return results
