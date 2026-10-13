"""Checks for AWS::GameLift::MatchmakingConfiguration."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, read
from ..common.literals import known_scope, literal
from .ruleset_arn_region import ruleset_arn_region

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GAMELIFT_MATCHMAKING_RULESET_REGION': [CF+'aws-resource-gamelift-matchmakingconfiguration.html','https://docs.aws.amazon.com/gameliftservers/latest/apireference/API_MatchmakingRuleSet.html'],
}


def ruleset_region(ctx,resource,path):
    arn_verdict=ruleset_arn_region(ctx,resource,path)
    if arn_verdict is not None:return arn_verdict
    name=read(ctx,resource,path)
    refs=[r for r in ctx.design.relations if r.source_resource_id==resource.id and r.source_path==path]
    if not known_scope(resource) or not literal(name) or not re.fullmatch(r'[A-Za-z0-9.-]{1,128}',name) or len(refs)!=1 or refs[0].condition:
        return 'NEEDS_REVIEW'
    other=ctx.by_id.get(refs[0].target_resource_id)
    if other is None or other.type!='AWS::GameLift::MatchmakingRuleSet' or not known_scope(other) or (other.scope.account,other.scope.environment)!=(resource.scope.account,resource.scope.environment):
        return 'NEEDS_REVIEW'
    if any(r.template is not None and r.template.state.value!='KNOWN' for r in (resource,other)):
        return 'NEEDS_REVIEW'
    actual=value(ctx,other,'/properties/Name')
    if not literal(actual) or actual!=name:
        return 'NEEDS_REVIEW'
    ctx.evidence.extend(refs[0].evidence_ids)
    return 'PASS' if other.scope.region==resource.scope.region else 'FAIL'


@resource_check('AWS::GameLift::MatchmakingConfiguration')
def evaluate_gamelift_matchmaking_ruleset_region(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::GameLift::MatchmakingConfiguration':
        path='/properties/RuleSetName'
        if value(ctx,resource,path) is not ABSENT:
            emit('GAMELIFT_MATCHMAKING_RULESET_REGION',path,ruleset_region(ctx,resource,path),'explicit rule-set ARN Region or a named unique rule-set reference establishes Region comparison; contradictory, conditional and unknown evidence remains reviewable; live existence is not certified')
    return results
