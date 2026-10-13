"""Checks for AWS::CodePipeline::Pipeline."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEPIPELINE_ARTIFACT_REGIONS': [CF+'aws-resource-codepipeline-pipeline.html'],
}


def region(raw):
 return isinstance(raw,str) and bool(re.fullmatch(r'[a-z]+(?:-[a-z]+)+-[0-9]+',raw))


@resource_check('AWS::CodePipeline::Pipeline')
def evaluate_codepipeline_artifact_regions(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 home=resource.scope.region;required={home} if region(home) else set();pending=not region(home)
 actions=list(expand(ctx,resource,'/properties/Stages/*/Actions/*'))
 if not actions:pending=True
 cross=False
 for p in actions:
  r=get(p+'/Region')
  if region(r):
   required.add(r)
   if region(home) and r!=home:cross=True
  else:pending=True
 stores=get('/properties/ArtifactStores');known=set();store_pending=False
 if isinstance(stores,list):
  for i in range(len(stores)):
   r=get('/properties/ArtifactStores/'+str(i)+'/Region')
   if region(r):known.add(r)
   else:store_pending=True
  verdict='FAIL' if required-known and not store_pending else 'NEEDS_REVIEW' if pending or store_pending else 'PASS'
 elif stores is ABSENT:verdict='FAIL' if cross else 'NEEDS_REVIEW' if pending else 'NOT_APPLICABLE'
 else:verdict='NEEDS_REVIEW'
 emit('CODEPIPELINE_ARTIFACT_REGIONS','/properties/ArtifactStores',verdict,'explicit ArtifactStores must cover pipeline and explicit action Regions; known cross-region action requires ArtifactStores; omitted/unknown action Region and unresolved store entries remain held; bucket existence/Region and store exclusivity are separate')
 return results
