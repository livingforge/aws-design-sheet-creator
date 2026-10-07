"""SES After reference scope and declared creation prerequisite."""
from ...template_dependencies import members, ordering
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'SES_RECEIPT_RULE_AFTER_SCOPE':[CF+'aws-resource-ses-receiptrule.html',CF+'aws-attribute-dependson.html']}


def rule_set(ctx,r):
    path='/properties/RuleSetName';raw=read(ctx,r,path)
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if refs:
        other=linked(ctx,r,path,'AWS::SES::ReceiptRuleSet')
        if not resolved(other):return None
        name=value(ctx,other,'/properties/RuleSetName')
        if raw is not ABSENT and (not literal(raw) or raw!=name):return None
        return ('name',name) if literal(name) and name else ('resource',other.id) if name is ABSENT else None
    return ('name',raw) if literal(raw) and raw else None


def after(ctx,r):
    given=value(ctx,r,'/properties/After')
    if given is ABSENT or given is None:return 'NOT_APPLICABLE'
    if not resolved(r):return 'NEEDS_REVIEW'
    other=linked(ctx,r,'/properties/After',r.type)
    if not resolved(other):return 'NEEDS_REVIEW'
    if other.id==r.id:return 'FAIL'
    raw=read(ctx,r,'/properties/After')
    if raw is not ABSENT and (not literal(raw) or raw!=value(ctx,other,'/properties/Rule/Name')):return 'NEEDS_REVIEW'
    a,b=rule_set(ctx,r),rule_set(ctx,other)
    if a is None or b is None or a[0]!=b[0]:return 'NEEDS_REVIEW'
    if a!=b:return 'FAIL'
    if other not in members(ctx.design,r):return 'NEEDS_REVIEW'
    try:return ordering(ctx,'SES_RECEIPT_RULE_AFTER_SCOPE',[other])['verdict']
    except RecursionError:return 'NEEDS_REVIEW'


@resource_check('AWS::SES::ReceiptRule')
def evaluate_ses_rule_order(design,resource):
    if resource.type!='AWS::SES::ReceiptRule':return []
    ctx=_Context(design,resource)
    f=ctx.finding('SES_RECEIPT_RULE_AFTER_SCOPE','/properties/After',after(ctx,resource),'After names a rule in the same receipt rule set that must precede this rule. An explicit same-template dependency/reference can establish creation order; self references and cycles fail. Missing template membership, ambiguous names and external/pre-existing rules remain reviewable. PASS covers declared identity and ordering, not deployed rule existence.')
    f['source_checked_at']='2026-10-04';return [f]
