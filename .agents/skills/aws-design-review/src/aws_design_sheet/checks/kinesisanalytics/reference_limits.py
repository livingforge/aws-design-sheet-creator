"""Page-listed literal string limits for SQL Analytics reference data."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
BASE='aws-properties-kinesisanalytics-applicationreferencedatasource-'
SOURCES={'KINESIS_ANALYTICS_REFERENCE_STRING_LIMITS':[CF+'aws-resource-kinesisanalytics-applicationreferencedatasource.html']+[CF+BASE+page+'.html' for page in ('referencedatasource','s3referencedatasource','referenceschema','recordcolumn','recordformat','mappingparameters','jsonmappingparameters','csvmappingparameters')]}
ROOT='ReferenceDataSource/'
SCHEMA=ROOT+'ReferenceSchema/'
MAPPING=SCHEMA+'RecordFormat/MappingParameters/'
SPECS=[('ApplicationName',1,128,r'[a-zA-Z0-9_.-]+'),(ROOT+'TableName',1,32,None),
       (ROOT+'S3ReferenceDataSource/FileKey',1,1024,None),
       (SCHEMA+'RecordColumns/*/SqlType',1,None,None),
       (MAPPING+'JSONMappingParameters/RecordRowPath',1,None,None)]
SPECS += [(ROOT+'S3ReferenceDataSource/'+key,1,2048,r'arn:.*') for key in ('BucketARN','ReferenceRoleARN')]
SPECS += [(MAPPING+'CSVMappingParameters/'+key,1,None,None) for key in ('RecordColumnDelimiter','RecordRowDelimiter')]


@resource_check('AWS::KinesisAnalytics::ApplicationReferenceDataSource')
def evaluate_kinesisanalytics_reference_limits(design,resource):
    if resource.type!='AWS::KinesisAnalytics::ApplicationReferenceDataSource':return []
    ctx=_Context(design,resource);results=[]
    for suffix,low,high,pattern in SPECS:
        for path in expand(ctx,resource,'/properties/'+suffix):
            raw=value(ctx,resource,path)
            if raw is ABSENT:continue
            verdict='NEEDS_REVIEW'
            if path.count('/')==('/properties/'+suffix).count('/') and isinstance(raw,str) and '${' not in raw and '{{' not in raw:
                valid=len(raw)>=low and (high is None or len(raw)<=high) and (pattern is None or re.fullmatch(pattern,raw) is not None)
                verdict='PASS' if valid else 'FAIL'
            f=ctx.finding('KINESIS_ANALYTICS_REFERENCE_STRING_LIMITS',path,verdict,
                'Published character bounds and literal pattern only. No SQL type grammar, JSONPath semantics, ARN existence, permissions or runtime availability is inferred. Unknown values remain reviewable.')
            f['source_checked_at']='2026-10-04';results.append(f)
    return results
