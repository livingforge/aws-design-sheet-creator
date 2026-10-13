"""Published scalar bounds and column count for SQL Analytics application input."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
PAGES=('input','inputschema','inputparallelism','inputprocessingconfiguration','inputlambdaprocessor','kinesisstreamsinput','kinesisfirehoseinput','recordcolumn','recordformat','mappingparameters','csvmappingparameters','jsonmappingparameters')
SOURCES={'KINESIS_ANALYTICS_INPUT_LEAF_LIMITS':[CF+'aws-resource-kinesisanalytics-application.html']+[CF+'aws-properties-kinesisanalytics-application-'+p+'.html' for p in PAGES]}
ROOT='Inputs/*/'
SCHEMA=ROOT+'InputSchema/'
MAPPING=SCHEMA+'RecordFormat/MappingParameters/'
STRINGS=[('ApplicationCode',0,102400,None),('ApplicationDescription',0,1024,None),('ApplicationName',1,128,r'[a-zA-Z0-9_.-]+'),
 (ROOT+'NamePrefix',1,32,None),(SCHEMA+'RecordEncoding',0,None,'UTF-8'),(SCHEMA+'RecordColumns/*/SqlType',1,None,None),
 (MAPPING+'JSONMappingParameters/RecordRowPath',1,None,None)]
STRINGS += [(ROOT+source+'/'+key,1,2048,r'arn:.*') for source in ('KinesisStreamsInput','KinesisFirehoseInput','InputProcessingConfiguration/InputLambdaProcessor') for key in ('ResourceARN','RoleARN')]
STRINGS += [(MAPPING+'CSVMappingParameters/'+key,1,None,None) for key in ('RecordColumnDelimiter','RecordRowDelimiter')]


@resource_check('AWS::KinesisAnalytics::Application')
def evaluate_kinesisanalytics_input_limits(design,resource):
    if resource.type!='AWS::KinesisAnalytics::Application':return []
    ctx=_Context(design,resource);results=[];seen=set()
    def emit(path,verdict):
        if (path,verdict) in seen:return
        seen.add((path,verdict))
        f=ctx.finding('KINESIS_ANALYTICS_INPUT_LEAF_LIMITS',path,verdict,
            'Published literal character bounds/patterns, InputParallelism.Count 1..64 and RecordColumns count 1..1000. SQL program semantics, JSONPath, ARN existence, permissions and live service availability are separate. Unknown values remain reviewable.')
        f['source_checked_at']='2026-10-04';results.append(f)
    for suffix,low,high,pattern in STRINGS:
        for path in expand(ctx,resource,'/properties/'+suffix):
            raw=value(ctx,resource,path)
            if raw is ABSENT:continue
            verdict='NEEDS_REVIEW'
            complete=path.count('/')==('/properties/'+suffix).count('/')
            if complete and isinstance(raw,str) and '${' not in raw and '{{' not in raw:
                valid=len(raw)>=low and (high is None or len(raw)<=high) and (pattern is None or re.fullmatch(pattern,raw) is not None)
                verdict='PASS' if valid else 'FAIL'
            emit(path,verdict)
    for suffix,kind,high in ((ROOT+'InputParallelism/Count',int,64),(SCHEMA+'RecordColumns',list,1000)):
        for path in expand(ctx,resource,'/properties/'+suffix):
            raw=value(ctx,resource,path)
            if raw is ABSENT:continue
            verdict='NEEDS_REVIEW'
            if path.count('/')==('/properties/'+suffix).count('/') and type(raw) is kind:
                n=len(raw) if kind is list else raw
                verdict='PASS' if 1<=n<=high else 'FAIL'
            emit(path,verdict)
    return results
