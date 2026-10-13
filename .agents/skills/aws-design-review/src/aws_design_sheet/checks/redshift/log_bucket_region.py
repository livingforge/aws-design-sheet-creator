"""Checks for AWS::Redshift::Cluster."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.script_bucket_region import script_bucket_region

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'REDSHIFT_LOG_BUCKET_REGION': [CF+'aws-properties-redshift-cluster-loggingproperties.html'],
}


@resource_check('AWS::Redshift::Cluster')
def evaluate_redshift_log_bucket_region(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Redshift::Cluster':
        path='/properties/LoggingProperties/BucketName'
        if value(ctx,resource,path) is not ABSENT:
            emit('REDSHIFT_LOG_BUCKET_REGION',path,script_bucket_region(ctx,resource,path),'explicit named uniquely linked bucket must share cluster Region; AZ placement, unresolved references, actual bucket existence and permissions remain held')
    return results
