"""Region evidence carried by a documented GameLift rule-set ARN."""
import re
from ..common.context_values import value
from ..common.field_reads import read
from ..common.literals import literal
from ..common.scoped_resolution import resolved


def ruleset_arn_region(ctx,r,path):
    raw=read(ctx,r,path)
    if not resolved(r) or not literal(raw):return None
    match=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:gamelift:([a-z0-9-]+):([0-9]{12})?:matchmakingruleset/([A-Za-z0-9.-]{1,128})',raw)
    if match is None:return None
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if refs:
        if len(refs)!=1 or refs[0].condition:return 'NEEDS_REVIEW'
        other=ctx.by_id.get(refs[0].target_resource_id)
        if not resolved(other) or other.type!='AWS::GameLift::MatchmakingRuleSet' or other.scope.environment!=r.scope.environment:return 'NEEDS_REVIEW'
        if other.scope.region!=match[1] or value(ctx,other,'/properties/Name')!=match[3]:return 'NEEDS_REVIEW'
        if match[2] and other.scope.account!=match[2]:return 'NEEDS_REVIEW'
        ctx.evidence.extend(refs[0].evidence_ids)
    return 'PASS' if match[1]==r.scope.region else 'FAIL'
