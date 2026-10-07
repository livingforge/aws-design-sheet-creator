"""Kendra search intent index account and Region evidence."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked
from ..common.field_reads import read
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

SOURCES={'LEX_KENDRA_INDEX_SCOPE':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lex-bot-kendraconfiguration.html']}


def scope(ctx,r,path):
    if not resolved(r):return 'NEEDS_REVIEW'
    raw=read(ctx,r,path)
    match=re.fullmatch(r'arn:aws[a-zA-Z-]*:kendra:([a-z]+-(?:[a-z]+-)*[0-9]):([0-9]{12}):index/[a-zA-Z0-9][a-zA-Z0-9_-]*',raw) if literal(raw) and len(raw)<=2048 else None
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if match:
        if refs:
            if len(refs)!=1 or refs[0].condition:return 'NEEDS_REVIEW'
            other=ctx.by_id.get(refs[0].target_resource_id)
            if not resolved(other) or other.type!='AWS::Kendra::Index' or other.scope.environment!=r.scope.environment:return 'NEEDS_REVIEW'
            if (other.scope.region,other.scope.account)!=(match[1],match[2]):return 'NEEDS_REVIEW'
            ctx.evidence.extend(refs[0].evidence_ids)
        return 'PASS' if (r.scope.region,r.scope.account)==(match[1],match[2]) else 'FAIL'
    other=linked(ctx,r,path,'AWS::Kendra::Index')
    return 'PASS' if resolved(other) else 'NEEDS_REVIEW'


@resource_check('AWS::Lex::Bot')
def evaluate_lex_kendra_scope(design,resource):
    if resource.type!='AWS::Lex::Bot':return []
    ctx=_Context(design,resource);results=[];pattern='/properties/BotLocales/*/Intents/*/KendraConfiguration/KendraIndex'
    for path in expand(ctx,resource,pattern):
        verdict=scope(ctx,resource,path) if path.count('/')==pattern.count('/') else 'NEEDS_REVIEW'
        f=ctx.finding('LEX_KENDRA_INDEX_SCOPE',path,verdict,'A Kendra search intent index must share the bot account and Region. Use a documented index ARN or an explicit unique same-scope Index reference. Conditional, contradictory, unknown or unsupported reference forms remain reviewable; no live existence or permission claim.')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
