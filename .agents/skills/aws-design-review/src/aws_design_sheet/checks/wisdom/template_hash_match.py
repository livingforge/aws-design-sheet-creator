"""Checks for AWS::Wisdom::MessageTemplateVersion."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES = {
    'WISDOM_TEMPLATE_HASH_MATCH': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-wisdom-messagetemplateversion.html',
    ],
}


@resource_check('AWS::Wisdom::MessageTemplateVersion')
def evaluate_wisdom_template_hash_match(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::Wisdom::MessageTemplateVersion':
        p='/properties/MessageTemplateContentSha256';raw=get(p)
        if raw is not ABSENT:
            template=linked(ctx,resource,'/properties/MessageTemplateArn','AWS::Wisdom::MessageTemplate');other=value(ctx,template,p) if template else None
            valid=lambda x:literal(x) and bool(re.fullmatch('[a-f0-9]{64}',x))
            emit('WISDOM_TEMPLATE_HASH_MATCH',p,'NEEDS_REVIEW' if not valid(raw) or not valid(other) else 'PASS' if raw==other else 'FAIL','compares explicit hash with linked template declared current content hash; no hash is computed or fetched and stale/external LATEST state remains unverified')
    return results
