"""Checks for AWS::GameLift::ContainerFleet."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.script_bucket_region import script_bucket_region

SOURCES = {
    'GAMELIFT_CONTAINER_LOG_BUCKET_REGION': ['https://docs.aws.amazon.com/gameliftservers/latest/apireference/API_LogConfiguration.html'],
}


@resource_check('AWS::GameLift::ContainerFleet')
def evaluate_gamelift_container_log_bucket_region(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    def enum(rule,path,allowed):
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            emit(rule,path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','explicit case-sensitive API values only; substitutions, unknown input and omitted defaults remain held')
    if resource.type=='AWS::GameLift::ContainerFleet':
        path='/properties/LogConfiguration/S3BucketName'
        if value(ctx,resource,path) is not ABSENT:
            verdict=script_bucket_region(ctx,resource,path) if value(ctx,resource,'/properties/LogConfiguration/LogDestination')=='S3' else 'NEEDS_REVIEW'
            emit('GAMELIFT_CONTAINER_LOG_BUCKET_REGION',path,verdict,'explicit S3 log destination and named unique bucket link must share fleet home Region; other destinations, missing defaults, permissions and conditional requiredness remain held')
    return results
