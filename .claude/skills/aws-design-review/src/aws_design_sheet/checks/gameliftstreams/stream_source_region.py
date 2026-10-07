"""Checks for AWS::GameLiftStreams::Application."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, read
from ..common.literals import known_scope, literal
from ..common.template_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GAMELIFT_STREAM_SOURCE_REGION': [CF+'aws-resource-gameliftstreams-application.html'],
}


def application_region(ctx,resource,path):
    uri=read(ctx,resource,path)
    match=re.fullmatch(r's3://([a-z0-9.-]{3,63})(?:/[^\s?#]*)?',uri) if literal(uri) and len(uri)<=1024 else None
    refs=[r for r in ctx.design.relations if r.source_resource_id==resource.id and r.source_path==path]
    if not match or not known_scope(resource) or not resolved(resource) or len(refs)!=1 or refs[0].condition:
        return 'NEEDS_REVIEW'
    bucket=ctx.by_id.get(refs[0].target_resource_id)
    if not resolved(bucket) or bucket.type!='AWS::S3::Bucket' or not known_scope(bucket) or bucket.scope.environment!=resource.scope.environment:
        return 'NEEDS_REVIEW'
    actual=value(ctx,bucket,'/properties/BucketName')
    if not literal(actual) or actual!=match[1]:return 'NEEDS_REVIEW'
    ctx.evidence.extend(refs[0].evidence_ids)
    return 'PASS' if bucket.scope.region==resource.scope.region else 'FAIL'


@resource_check('AWS::GameLiftStreams::Application')
def evaluate_gameliftstreams_stream_source_region(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::GameLiftStreams::Application':
        path='/properties/ApplicationSourceUri'
        if value(ctx,resource,path) is not ABSENT:
            emit('GAMELIFT_STREAM_SOURCE_REGION',path,application_region(ctx,resource,path),'explicit S3 URI bucket must match unique linked bucket identity and application Region; content completeness, executability, permissions and external buckets remain held')
    return results
