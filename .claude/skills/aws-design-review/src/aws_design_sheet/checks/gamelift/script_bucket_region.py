"""Checks for AWS::GameLift::Script."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.script_bucket_region import script_bucket_region

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GAMELIFT_SCRIPT_BUCKET_REGION': [CF+'aws-resource-gamelift-script.html'],
}


@resource_check('AWS::GameLift::Script')
def evaluate_gamelift_script_bucket_region(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::GameLift::Script':
        path='/properties/StorageLocation/Bucket'
        if value(ctx,resource,path) is not ABSENT:
            emit('GAMELIFT_SCRIPT_BUCKET_REGION',path,script_bucket_region(ctx,resource,path),'explicit named uniquely linked bucket must share script Region; existence, contents, versions and role permissions remain external')
    return results
