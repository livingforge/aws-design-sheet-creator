"""Explicit LF-tag definitions, lowercase values and prerequisite template ordering."""
import re
from ...template_dependencies import members, ordering
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
RULE='LAKEFORMATION_ASSOCIATION_TAG_DEFINITIONS'
SOURCES={RULE:[CF+'aws-resource-lakeformation-tag.html',CF+'aws-properties-lakeformation-tagassociation-lftagpair.html',CF+'aws-attribute-dependson.html','https://docs.aws.amazon.com/lake-formation/latest/dg/lf-tag-considerations.html']}


def canonical(raw):
    return raw.lower() if literal(raw) and raw.isascii() else None


def catalog(ctx,r,path,default=False):
    raw=value(ctx,r,path)
    if raw is ABSENT and default:raw=r.scope.account
    return raw if isinstance(raw,str) and re.fullmatch(r'[0-9]{12}',raw) else None


def check(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    rows=value(ctx,r,'/properties/LFTags')
    if not isinstance(rows,list) or not 1<=len(rows)<=50:return 'NEEDS_REVIEW'
    tags=[];pending=False
    for i in range(len(rows)):
        base=f'/properties/LFTags/{i}/';tag=linked(ctx,r,base+'TagKey','AWS::LakeFormation::Tag')
        if not resolved(tag):pending=True;continue
        own=catalog(ctx,r,base+'CatalogId');other=catalog(ctx,tag,'/properties/CatalogId',True)
        key=canonical(read(ctx,r,base+'TagKey'));defined=canonical(value(ctx,tag,'/properties/TagKey'))
        if own is None or other!=own or defined is None or (read(ctx,r,base+'TagKey') is not ABSENT and key!=defined):pending=True;continue
        wanted=value(ctx,r,base+'TagValues');allowed=value(ctx,tag,'/properties/TagValues')
        if not isinstance(wanted,list) or not 1<=len(wanted)<=50 or not isinstance(allowed,list) or not 1<=len(allowed)<=1000:pending=True;continue
        requested=[canonical(v) for v in wanted];defined_values=[canonical(v) for v in allowed]
        if None not in defined_values and any(v is not None and v not in defined_values for v in requested):return 'FAIL'
        if None in requested or any(v not in defined_values for v in requested):pending=True
        tags.append(tag)
    if pending or len(tags)!=len(rows):return 'NEEDS_REVIEW'
    pool=members(ctx.design,r)
    if not pool or any(t not in pool for t in tags):return 'NEEDS_REVIEW'
    try:return ordering(ctx,RULE,tags)['verdict']
    except RecursionError:return 'NEEDS_REVIEW'


@resource_check('AWS::LakeFormation::TagAssociation')
def evaluate_lakeformation_tag_definitions(design,resource):
    if resource.type!='AWS::LakeFormation::TagAssociation':return []
    ctx=_Context(design,resource)
    f=ctx.finding(RULE,'/properties/LFTags',check(ctx,resource),'Assigned LF-tag keys and values must be predefined. Compare explicit same-scope Tag references and catalog identity, lowercasing ASCII keys/values as documented, then establish same-template prerequisite ordering. Missing values in a complete declared definition fail. External/pre-existing tags, unknown definitions, omitted required association CatalogId, Unicode casing and missing template membership remain reviewable. PASS does not certify deployed tags or permissions.')
    f['source_checked_at']='2026-10-04';return [f]
