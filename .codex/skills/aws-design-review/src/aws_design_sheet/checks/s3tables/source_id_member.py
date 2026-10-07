"""Checks for AWS::S3Tables::Table."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'S3TABLES_SOURCE_ID_MEMBER': [CF+'aws-properties-s3tables-table-icebergpartitionfield.html',CF+'aws-properties-s3tables-table-icebergsortfield.html'],
}


@resource_check('AWS::S3Tables::Table')
def evaluate_s3tables_source_id_member(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::S3Tables::Table':
  base='/properties/IcebergMetadata';raw=get(base+'/IcebergSchema/SchemaFieldList');ids=[];pending=not isinstance(raw,list) or get(base+'/IcebergSchemaV2') is not ABSENT
  for i in range(len(raw)) if isinstance(raw,list) else ():
   ident=get(base+'/IcebergSchema/SchemaFieldList/'+str(i)+'/Id')
   if type(ident) is int:ids.append(ident)
   else:pending=True
  for kind in ('IcebergPartitionSpec','IcebergSortOrder'):
   for p in expand(ctx,resource,base+'/'+kind+'/Fields/*/SourceId'):
    ident=get(p);v='NEEDS_REVIEW' if type(ident) is not int else 'PASS' if ident in ids else 'NEEDS_REVIEW' if pending else 'FAIL'
    emit('S3TABLES_SOURCE_ID_MEMBER',p,v,'SourceId must occur in known flat schema IDs; omitted generated IDs and V2/nested schema identity remain held')
 return results
