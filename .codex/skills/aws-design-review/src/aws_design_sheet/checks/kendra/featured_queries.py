"""Known cross-set query collisions; never infer a complete live index inventory."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

SOURCES={'KENDRA_FEATURED_QUERY_COLLISION':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kendra-featuredresultsset.html','https://docs.aws.amazon.com/kendra/latest/dg/featured-results.html','https://docs.aws.amazon.com/kendra/latest/APIReference/API_CreateFeaturedResultsSet.html']}
TYPE='AWS::Kendra::FeaturedResultsSet'


def index_identity(ctx,r):
    if not resolved(r):return None
    path='/properties/IndexId';raw=read(ctx,r,path)
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if refs:
        index=linked(ctx,r,path,'AWS::Kendra::Index')
        # A literal ID plus a logical reference cannot be reconciled without
        # the deployed index ID. Do not assume that they describe one index.
        return ('logical',index.id) if resolved(index) and raw is ABSENT else None
    return ('literal',raw) if literal(raw) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9-]{35}',raw) else None


def queries(ctx,r):
    raw=value(ctx,r,'/properties/QueryTexts')
    if not isinstance(raw,list) or len(raw)>49:return None
    result=set()
    for i in range(len(raw)):
        text=value(ctx,r,f'/properties/QueryTexts/{i}')
        # Unicode case conversion is not specified sufficiently by the guide.
        if literal(text) and text.isascii():
            result.add(re.sub(r'[ \t\r\n\v\f]+$',' ',text.lower()))
    return result


@resource_check('AWS::Kendra::FeaturedResultsSet')
def evaluate_kendra_featured_queries(design,resource):
    if resource.type!=TYPE:return []
    ctx=_Context(design,resource);identity=index_identity(ctx,resource)
    own=queries(ctx,resource);verdict='NEEDS_REVIEW'
    if resolved(resource) and value(ctx,resource,'/properties/QueryTexts')==[]:verdict='NOT_APPLICABLE'
    if identity is not None and own:
        for other in design.resources:
            if other.id==resource.id or other.type!=TYPE or other.scope!=resource.scope:continue
            if index_identity(ctx,other)!=identity:continue
            theirs=queries(ctx,other)
            if theirs and own & theirs:verdict='FAIL';break
    f=ctx.finding('KENDRA_FEATURED_QUERY_COLLISION','/properties/QueryTexts',verdict,'Featured result sets in one index cannot share query text, regardless of ACTIVE/INACTIVE status. Compare known ASCII queries after documented lowercase and trailing-whitespace-to-one-space normalization. A known cross-set collision fails. No collision does not establish complete live inventory; external sets, Unicode normalization and within-set duplicate acceptance remain reviewable.')
    f['source_checked_at']='2026-10-04';return [f]
