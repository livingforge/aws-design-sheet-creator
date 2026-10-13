"""Checks for AWS::GameLift::Build, AWS::GameLift::MatchmakingRuleSet."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, read
from ..common.json_verdict import json_verdict
from ..common.literals import known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GAMELIFT_RULESET_JSON': [CF+'aws-resource-gamelift-matchmakingruleset.html'],
    'GAMELIFT_BUILD_BUCKET_SCOPE': [CF+'aws-resource-gamelift-build.html'],
}


def build_bucket_scope(ctx,resource,path):
    name=read(ctx,resource,path)
    refs=[r for r in ctx.design.relations if r.source_resource_id==resource.id and r.source_path==path]
    if not known_scope(resource) or not literal(name) or not re.fullmatch(r'[a-z0-9.-]{3,63}',name) or len(refs)!=1 or refs[0].condition:
        return 'NEEDS_REVIEW'
    bucket=ctx.by_id.get(refs[0].target_resource_id)
    if bucket is None or bucket.type!='AWS::S3::Bucket' or not known_scope(bucket) or bucket.scope.environment!=resource.scope.environment:
        return 'NEEDS_REVIEW'
    if any(r.template is not None and r.template.state.value!='KNOWN' for r in (resource,bucket)):
        return 'NEEDS_REVIEW'
    actual=value(ctx,bucket,'/properties/BucketName')
    if not literal(actual) or actual!=name:
        return 'NEEDS_REVIEW'
    ctx.evidence.extend(refs[0].evidence_ids)
    return 'PASS' if (bucket.scope.account,bucket.scope.region)==(resource.scope.account,resource.scope.region) else 'FAIL'


@resource_check('AWS::GameLift::MatchmakingRuleSet', 'AWS::GameLift::Build')
def evaluate_gamelift_data(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::GameLift::MatchmakingRuleSet':
        path='/properties/RuleSetBody'
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            emit('GAMELIFT_RULESET_JSON',path,json_verdict(raw),'bounded JSON syntax excludes comments; FlexMatch content grammar remains separate')
    if resource.type=='AWS::GameLift::Build':
        path='/properties/StorageLocation/Bucket'
        if value(ctx,resource,path) is not ABSENT:
            emit('GAMELIFT_BUILD_BUCKET_SCOPE',path,build_bucket_scope(ctx,resource,path),'explicitly named uniquely linked source bucket must share build account and Region; existence, object contents and role permissions remain external')
    return results
