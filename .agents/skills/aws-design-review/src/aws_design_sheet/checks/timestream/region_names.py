"""Checks for AWS::Timestream::ScheduledQuery, AWS::Timestream::Table."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import known_scope, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'TIMESTREAM_TABLE_NAME_UNIQUE': [CF+'aws-resource-timestream-table.html'],
    'TIMESTREAM_QUERY_NAME_UNIQUE': [CF+'aws-resource-timestream-scheduledquery.html'],
}


def database(ctx,resource):
 if not known_scope(resource):return None
 target=linked(ctx,resource,'/properties/DatabaseName','AWS::Timestream::Database')
 if target:return ('resource',target.id)
 name=value(ctx,resource,'/properties/DatabaseName')
 return ('name',name) if literal(name) and re.fullmatch(r'[A-Za-z0-9_.-]{3,256}',name) else None


@resource_check('AWS::Timestream::Table','AWS::Timestream::ScheduledQuery')
def evaluate_timestream_region_names(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 table=resource.type=='AWS::Timestream::Table'
 path='/properties/'+('TableName' if table else 'ScheduledQueryName');name=get(path)
 own=database(ctx,resource) if table else ('scope',) if known_scope(resource) else None
 pending=not literal(name) or own is None;duplicate=False
 for other in design.resources:
  if other.id==resource.id or other.type!=resource.type or other.scope!=resource.scope:continue
  other_name=value(ctx,other,path)
  if literal(name) and literal(other_name) and name!=other_name:continue
  identity=database(ctx,other) if table else ('scope',) if known_scope(other) else None
  if own and identity and own[0]==identity[0] and own!=identity:continue
  if literal(name) and name==other_name and own and identity==own:duplicate=True
  else:pending=True
 emit('TIMESTREAM_TABLE_NAME_UNIQUE' if table else 'TIMESTREAM_QUERY_NAME_UNIQUE',path,'FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS','explicit names must be unique within same design scope, and for tables same comparable database; generated/unknown names, mixed database identities and external resources remain unverified')
 return results
