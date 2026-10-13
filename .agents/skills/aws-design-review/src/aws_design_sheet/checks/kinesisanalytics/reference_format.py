"""Checks for AWS::KinesisAnalytics::ApplicationReferenceDataSource."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'KINESIS_ANALYTICS_REFERENCE_FORMAT': [CF+'aws-properties-kinesisanalytics-applicationreferencedatasource-recordformat.html'],
}


@resource_check('AWS::KinesisAnalytics::ApplicationReferenceDataSource')
def evaluate_kinesisanalytics_reference_format(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::KinesisAnalytics::ApplicationReferenceDataSource':
        path='/properties/ReferenceDataSource/ReferenceSchema/RecordFormat/RecordFormatType'
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            emit('KINESIS_ANALYTICS_REFERENCE_FORMAT',path,'PASS' if raw in ('JSON','CSV') else 'FAIL' if literal(raw) else 'NEEDS_REVIEW','explicit reference RecordFormatType must be JSON or CSV; unknown format, other table/ARN constraints and actual reference data remain held')
    return results
