"""Checks for AWS::CodePipeline::CustomActionType."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEPIPELINE_QUERYABLE_COUNT': [CF+'aws-properties-codepipeline-customactiontype-configurationproperties.html'],
}


@resource_check('AWS::CodePipeline::CustomActionType')
def evaluate_codepipeline_queryable_count(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::CodePipeline::CustomActionType':
  p='/properties/ConfigurationProperties';raw=get(p)
  if raw is not ABSENT:
   flags=[get(p+'/'+str(i)+'/Queryable') for i in range(len(raw))] if isinstance(raw,list) else [raw]
   n=sum(x is True for x in flags);pending=any(x is not True and x is not False for x in flags)
   emit('CODEPIPELINE_QUERYABLE_COUNT',p,'FAIL' if n>1 else 'NEEDS_REVIEW' if pending else 'PASS','at most one Queryable true; omitted and unresolved flags held without assumed defaults')
 return results
