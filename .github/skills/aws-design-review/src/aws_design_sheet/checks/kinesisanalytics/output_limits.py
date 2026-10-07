"""All page-listed string bounds for legacy Kinesis Analytics output properties."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'KINESIS_ANALYTICS_OUTPUT_STRING_LIMITS':[CF+'aws-resource-kinesisanalytics-applicationoutput.html']+[CF+'aws-properties-kinesisanalytics-applicationoutput-'+name+'.html' for name in ('output','kinesisstreamsoutput','kinesisfirehoseoutput','lambdaoutput')]}
SPECS=[('ApplicationName',1,128,r'[a-zA-Z0-9_.-]+'),('Output/Name',1,32,None)]+[('Output/'+dest+'/'+key,1,2048,r'arn:.*') for dest in ('KinesisStreamsOutput','KinesisFirehoseOutput','LambdaOutput') for key in ('ResourceARN','RoleARN')]


@resource_check('AWS::KinesisAnalytics::ApplicationOutput')
def evaluate_kinesisanalytics_output_limits(design,resource):
    if resource.type!='AWS::KinesisAnalytics::ApplicationOutput':return []
    ctx=_Context(design,resource);results=[]
    for suffix,low,high,pattern in SPECS:
        path='/properties/'+suffix;raw=value(ctx,resource,path)
        if raw is ABSENT:continue
        verdict='NEEDS_REVIEW'
        if isinstance(raw,str) and '${' not in raw and '{{' not in raw:
            verdict='PASS' if low<=len(raw)<=high and (pattern is None or re.fullmatch(pattern,raw)) else 'FAIL'
        f=ctx.finding('KINESIS_ANALYTICS_OUTPUT_STRING_LIMITS',path,verdict,'Documented character length and pattern only; empty known strings fail minimum length. Unresolved references remain reviewable. The loose arn:.* pattern does not prove a complete ARN, permissions or destination existence.')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
