"""Legacy WAF regional actions and XSS transformation value sets."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal
from .size_constraints import TRANSFORMS

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'WAFREGIONAL_RULE_ACTION_TYPE':[CF+'aws-properties-wafregional-webacl-action.html'],
 'WAFREGIONAL_XSS_TRANSFORMATION':[CF+'aws-properties-wafregional-xssmatchset-xssmatchtuple.html'],
 'WAF_XSS_TRANSFORMATION':[CF+'aws-properties-waf-xssmatchset-xssmatchtuple.html'],
}
SPECS={
 'AWS::WAFRegional::WebACL':('WAFREGIONAL_RULE_ACTION_TYPE','/properties/Rules/*/Action/Type',('ALLOW','BLOCK','COUNT')),
 'AWS::WAFRegional::XssMatchSet':('WAFREGIONAL_XSS_TRANSFORMATION','/properties/XssMatchTuples/*/TextTransformation',TRANSFORMS),
 'AWS::WAF::XssMatchSet':('WAF_XSS_TRANSFORMATION','/properties/XssMatchTuples/*/TextTransformation',TRANSFORMS),
}


@resource_check('AWS::WAFRegional::WebACL', 'AWS::WAFRegional::XssMatchSet', 'AWS::WAF::XssMatchSet')
def evaluate_waf_xss_and_actions(design,resource):
    if resource.type not in SPECS:return []
    ctx=_Context(design,resource);results=[]
    rule,pattern,allowed=SPECS[resource.type]
    for path in expand(ctx,resource,pattern):
        raw=value(ctx,resource,path)
        verdict='NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL'
        f=ctx.finding(rule,path,verdict,'legacy explicit enum only; default-action constraints, FieldToMatch/context, unknowns and post-support availability remain held; PASS does not imply creation support')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
