"""Checks for AWS::KinesisAnalytics::Application."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'KINESIS_ANALYTICS_INPUT_FORMAT': [CF+'aws-properties-kinesisanalytics-application-recordformat.html'],
}


@resource_check('AWS::KinesisAnalytics::Application')
def evaluate_kinesisanalytics_input_format(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::KinesisAnalytics::Application':
        for path in expand(ctx,resource,'/properties/Inputs/*/InputSchema/RecordFormat/RecordFormatType'):
            raw=value(ctx,resource,path)
            emit('KINESIS_ANALYTICS_INPUT_FORMAT',path,'PASS' if raw in ('JSON','CSV') else 'FAIL' if literal(raw) else 'NEEDS_REVIEW','explicit input RecordFormatType must be JSON or CSV; unknown formats and other missing leaf constraints remain held')
    return results
