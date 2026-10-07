"""Checks for AWS::IVS::StorageConfiguration."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.script_bucket_region import script_bucket_region

SOURCES = {
    'IVS_STORAGE_BUCKET_REGION': ['https://docs.aws.amazon.com/ivs/latest/RealTimeAPIReference/API_S3StorageConfiguration.html'],
}


@resource_check('AWS::IVS::StorageConfiguration')
def evaluate_ivs_storage_bucket_region(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::IVS::StorageConfiguration':
        path='/properties/S3/BucketName'
        if value(ctx,resource,path) is not ABSENT:
            emit('IVS_STORAGE_BUCKET_REGION',path,script_bucket_region(ctx,resource,path),'explicit named uniquely linked S3 bucket and storage configuration must share Region; Composition placement, external buckets and permissions remain held')
    return results
