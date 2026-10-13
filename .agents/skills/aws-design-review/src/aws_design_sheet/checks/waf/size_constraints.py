"""Legacy WAF Regional IP types and size-condition value sets."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'WAFREGIONAL_IP_DESCRIPTOR_TYPE':[CF+'aws-properties-wafregional-ipset-ipsetdescriptor.html'],
 'WAFREGIONAL_SIZE_CONDITION_VALUES':[CF+'aws-properties-wafregional-sizeconstraintset-sizeconstraint.html'],
 'WAF_SIZE_CONDITION_VALUES':[CF+'aws-properties-waf-sizeconstraintset-sizeconstraint.html'],
}
COMPARISONS=('EQ','NE','LE','LT','GE','GT')
TRANSFORMS=('NONE','COMPRESS_WHITE_SPACE','HTML_ENTITY_DECODE','LOWERCASE','CMD_LINE','URL_DECODE')


def classic_sizes(design,resource):
    ctx=_Context(design,resource);results=[];specs=[]
    if resource.type=='AWS::WAFRegional::IPSet':
        specs=[('WAFREGIONAL_IP_DESCRIPTOR_TYPE','/properties/IPSetDescriptors/*/Type',('IPV4','IPV6'))]
    if resource.type in ('AWS::WAF::SizeConstraintSet','AWS::WAFRegional::SizeConstraintSet'):
        rule='WAF_SIZE_CONDITION_VALUES' if resource.type=='AWS::WAF::SizeConstraintSet' else 'WAFREGIONAL_SIZE_CONDITION_VALUES'
        specs=[(rule,'/properties/SizeConstraints/*/'+key,allowed) for key,allowed in (('ComparisonOperator',COMPARISONS),('TextTransformation',TRANSFORMS))]
    seen=set()
    for rule,pattern,allowed in specs:
        for path in expand(ctx,resource,pattern):
            if (rule,path) in seen:continue
            seen.add((rule,path));raw=value(ctx,resource,path)
            verdict='NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL'
            f=ctx.finding(rule,path,verdict,'documented legacy literal values only; unknowns, CIDR consistency, FieldToMatch/context constraints and post-support service availability remain held; PASS does not imply creation support')
            f['source_checked_at']='2026-10-04';results.append(f)
    return results


@resource_check('AWS::WAF::SizeConstraintSet')
def evaluate_waf_size_constraints(design,resource):return classic_sizes(design,resource)


@resource_check('AWS::WAFRegional::IPSet','AWS::WAFRegional::SizeConstraintSet')
def evaluate_wafregional_size_constraints(design,resource):return classic_sizes(design,resource)
