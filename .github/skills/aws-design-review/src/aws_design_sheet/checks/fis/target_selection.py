"""Checks for AWS::FIS::ExperimentTemplate."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.map_cardinality import map_paths

SOURCES = {
    'FIS_TARGET_SELECTION': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-fis-experimenttemplate-experimenttemplatetarget.html',
    ],
}


@resource_check('AWS::FIS::ExperimentTemplate')
def evaluate_fis_target_selection(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::FIS::ExperimentTemplate':
  for p in map_paths(ctx,resource,'/properties/Targets'):
   a=get(p+'/ResourceArns');b=get(p+'/ResourceTags')
   def presence(x,t):return False if x is ABSENT or isinstance(x,t) and not x else True if isinstance(x,t) else None
   left=presence(a,list);right=presence(b,dict)
   v='NEEDS_REVIEW' if left is None or right is None or p=='/properties/Targets' else 'PASS' if left!=right else 'FAIL'
   emit('FIS_TARGET_SELECTION',p,v,'each plain-key target requires nonempty ResourceArns or ResourceTags, not both; dynamic/escaped keys and unknown collection presence held')
 return results
