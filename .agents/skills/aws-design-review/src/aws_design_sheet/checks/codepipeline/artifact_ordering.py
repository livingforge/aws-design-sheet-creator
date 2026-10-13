"""Checks for AWS::CodePipeline::Pipeline."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
GUIDE='https://docs.aws.amazon.com/codepipeline/latest/userguide/'
SOURCES = {
    'CODEPIPELINE_INPUT_PRECEDES': [CF+'aws-properties-codepipeline-pipeline-inputartifact.html',GUIDE+'action-requirements.html'],
    'CODEPIPELINE_PRIMARY_SOURCE': [CF+'aws-properties-codepipeline-pipeline-actiondeclaration.html',GUIDE+'action-reference-CodeBuild.html'],
}


@resource_check('AWS::CodePipeline::Pipeline')
def evaluate_codepipeline_artifact_ordering(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 actions=list(expand(ctx,resource,'/properties/Stages/*/Actions/*'));outputs=[];pending=False
 for action in actions:
  match=action.split('/')
  position=int(match[3]) if len(match)==6 and match[3].isdigit() else None
  order=get(action+'/RunOrder');order=1 if order is ABSENT else order
  for p in expand(ctx,resource,action+'/OutputArtifacts/*'):
   name=get(p+'/Name')
   if not literal(name) or position is None:pending=True
   else:outputs.append((name,action,position,order))
  if position is None:pending=True
 for action in actions:
  parts=action.split('/');stage=int(parts[3]) if len(parts)==6 and parts[3].isdigit() else None
  order=get(action+'/RunOrder');order=1 if order is ABSENT else order
  for p in expand(ctx,resource,action+'/InputArtifacts/*'):
   name=get(p+'/Name');matches=[x for x in outputs if x[0]==name] if literal(name) else []
   verdict='NEEDS_REVIEW'
   if literal(name) and stage is not None and not pending and len(matches)<=1:
    if not matches:verdict='FAIL'
    else:
     _,producer,previous,run=matches[0]
     if producer==action or previous>stage:verdict='FAIL'
     elif previous<stage:verdict='PASS'
     elif type(order) is int and type(run) is int and 1<=order<=999 and 1<=run<=999:verdict='PASS' if run<order else 'FAIL'
   emit('CODEPIPELINE_INPUT_PRECEDES',p,verdict,'input artifact must resolve uniquely to output of an earlier stage or lower RunOrder action; absent RunOrder defaults to documented 1; ambiguous outputs and unknown producer arrays/order remain held')
  provider=get(action+'/ActionTypeId/Provider')
  if provider!='CodeBuild':continue
  inputs=get(action+'/InputArtifacts');primary=get(action+'/Configuration/PrimarySource')
  verdict='NEEDS_REVIEW'
  if isinstance(inputs,list):
   names=[get(action+'/InputArtifacts/'+str(i)+'/Name') for i in range(len(inputs))]
   if primary is ABSENT and len(inputs)>1:verdict='FAIL'
   elif literal(primary):
    if primary in [n for n in names if literal(n)]:verdict='PASS'
    elif all(literal(n) for n in names):verdict='FAIL'
  emit('CODEPIPELINE_PRIMARY_SOURCE',action+'/Configuration/PrimarySource',verdict,'CodeBuild with multiple inputs requires PrimarySource naming an input; unknown configuration/names held; omitted single-input PrimarySource held due to conflicting guide prose')
 return results
