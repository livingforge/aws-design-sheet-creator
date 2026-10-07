"""Checks for AWS::MediaTailor::Function."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES = {
    'MEDIATAILOR_CHILD_NAMESPACE': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-mediatailor-function-functionref.html',
    ],
}


@resource_check('AWS::MediaTailor::Function')
def evaluate_mediatailor_child_namespace(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::MediaTailor::Function':
  for key in ('ConcurrentExecutorConfiguration','SequentialExecutorConfiguration'):
   p='/properties/'+key+'/FunctionList';raw=get(p)
   if raw is ABSENT:continue
   names=[];pending=not isinstance(raw,list);duplicate=False
   for i in range(len(raw)) if isinstance(raw,list) else ():
    name=get(p+'/'+str(i)+'/Alias')
    if name is ABSENT:name=get(p+'/'+str(i)+'/FunctionId')
    if not literal(name):pending=True;continue
    if name in names:duplicate=True
    names.append(name)
   emit('MEDIATAILOR_CHILD_NAMESPACE',p,'FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS','namespace uses Alias or FunctionId only when Alias absent; known duplicates fail despite unknown siblings; no fallback for unresolved Alias')
 return results
