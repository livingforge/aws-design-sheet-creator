"""Checks for AWS::AWSExternalAnthropic::Workspace."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES = {
    'ANTHROPIC_INFERENCE_GEO': [
        'https://schema.cloudformation.ap-northeast-1.amazonaws.com/CloudformationSchema.zip',
    ],
}


@resource_check('AWS::AWSExternalAnthropic::Workspace')
def evaluate_awsexternalanthropic_anthropic_inference_geo(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::AWSExternalAnthropic::Workspace':
  p='/properties/DataResidency/AllowedInferenceGeos';allowed=get(p);choice=get('/properties/DataResidency/DefaultInferenceGeo')
  if allowed is not ABSENT:
   names=[get(p+'/'+str(i)) for i in range(len(allowed))] if isinstance(allowed,list) else []
   v='NEEDS_REVIEW'
   if literal(choice) and isinstance(allowed,list):v='PASS' if choice in [x for x in names if literal(x)] else 'FAIL' if all(literal(x) for x in names) else 'NEEDS_REVIEW'
   emit('ANTHROPIC_INFERENCE_GEO',p,v,'explicit default inference geo must be among explicit allowed geos; omitted defaults and unknown entries held')
 return results
