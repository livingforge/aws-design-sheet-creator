"""Checks for AWS::GameLift::MatchmakingRuleSet."""
from ..registry import resource_check
from ..common.context_values import _Context
from .matchmaking_ruleset_region import ruleset_region

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GAMELIFT_RULESET_LOCAL_CONFIG_REGIONS': [CF+'aws-resource-gamelift-matchmakingruleset.html'],
}


def local_config_conflict(ctx,resource):
    if len(ctx.design.resources)>10000:return 'NEEDS_REVIEW'
    path='/properties/RuleSetName'
    for other in ctx.design.resources:
        if other.type!='AWS::GameLift::MatchmakingConfiguration':continue
        refs=[r for r in ctx.design.relations if r.source_resource_id==other.id and r.source_path==path]
        if len(refs)==1 and refs[0].target_resource_id==resource.id and ruleset_region(ctx,other,path)=='FAIL':
            return 'FAIL'
    # Input references never prove that every deployed consumer was enumerated.
    return 'NEEDS_REVIEW'


@resource_check('AWS::GameLift::MatchmakingRuleSet')
def evaluate_gamelift_ruleset_local_config_regions(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::GameLift::MatchmakingRuleSet':
        emit('GAMELIFT_RULESET_LOCAL_CONFIG_REGIONS','/properties/Name',local_config_conflict(ctx,resource),'prove Region conflicts in explicit named unique same-account/environment consumer links; unknown or external consumers and usage completeness remain held; no completeness PASS')
    return results
