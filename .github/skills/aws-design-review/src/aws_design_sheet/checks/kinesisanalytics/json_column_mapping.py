"""Checks for AWS::KinesisAnalytics::Application."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'KINESIS_ANALYTICS_JSON_COLUMN_MAPPING': [CF+'aws-properties-kinesisanalytics-application-recordcolumn.html'],
}


def mapping_presence(ctx,resource,path):
    if value(ctx,resource,path+'/InputSchema/RecordFormat/RecordFormatType')!='JSON':return 'NEEDS_REVIEW'
    base=path+'/InputSchema/RecordColumns'
    columns=value(ctx,resource,base)
    if not isinstance(columns,list) or not columns or len(columns)>1000:return 'NEEDS_REVIEW'
    pending=False
    for i in range(len(columns)):
        raw=value(ctx,resource,base+'/'+str(i)+'/Mapping')
        if raw is ABSENT:return 'FAIL'
        if not literal(raw):pending=True
    return 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::KinesisAnalytics::Application')
def evaluate_kinesisanalytics_json_column_mapping(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::KinesisAnalytics::Application':
        for path in expand(ctx,resource,'/properties/Inputs/*'):
            emit('KINESIS_ANALYTICS_JSON_COLUMN_MAPPING',path,mapping_presence(ctx,resource,path),'each explicit JSON-input column requires Mapping; only presence is checked, not JSONPath grammar or actual data correspondence; unknown/CSV inputs remain held')
    return results
