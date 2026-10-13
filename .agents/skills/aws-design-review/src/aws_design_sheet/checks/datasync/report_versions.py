"""Task report version applicability uses the transfer destination bucket."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'DATASYNC_REPORT_OBJECT_VERSION_APPLICABILITY':[CF+'aws-properties-datasync-task-taskreportconfig.html',CF+'aws-resource-datasync-task.html',CF+'aws-resource-datasync-locations3.html',CF+'aws-properties-s3-bucket-versioningconfiguration.html']}


@resource_check('AWS::DataSync::Task')
def evaluate_datasync_report_versions(design,resource):
    if resource.type!='AWS::DataSync::Task':return []
    ctx=_Context(design,resource);path='/properties/TaskReportConfig/ObjectVersionIds';raw=value(ctx,resource,path)
    if raw is ABSENT:return []
    verdict='NEEDS_REVIEW'
    if raw=='NONE':verdict='NOT_APPLICABLE'
    elif raw=='INCLUDE' and resolved(resource):
        location=linked(ctx,resource,'/properties/DestinationLocationArn','AWS::DataSync::LocationS3')
        bucket=linked(ctx,location,'/properties/S3BucketArn','AWS::S3::Bucket') if resolved(location) else None
        if resolved(bucket):
            status=value(ctx,bucket,'/properties/VersioningConfiguration/Status')
            if status=='Enabled':verdict='PASS'
            elif status=='Suspended':verdict='NOT_APPLICABLE'
    f=ctx.finding('DATASYNC_REPORT_OBJECT_VERSION_APPLICABILITY',path,verdict,
        'Object version reporting applies when versioning is Enabled on the transfer destination S3 bucket, not the report storage bucket. Suspended versioning is not applicable; missing/unknown/external evidence remains reviewable. The documentation does not establish that an inapplicable INCLUDE setting is rejected, so no rejection FAIL is inferred.')
    f['source_checked_at']='2026-10-04'
    return [f]
