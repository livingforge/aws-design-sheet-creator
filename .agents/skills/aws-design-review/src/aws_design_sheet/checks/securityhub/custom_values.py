"""Checks for AWS::SecurityHub::ConfigurationPolicy, AWS::SecurityHub::SecurityControl."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand
from ..common.map_cardinality import map_paths

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SECURITYHUB_CONTROL_CUSTOM_VALUE': [CF+'aws-properties-securityhub-securitycontrol-parameterconfiguration.html'],
    'SECURITYHUB_POLICY_CUSTOM_VALUE': [CF+'aws-properties-securityhub-configurationpolicy-parameterconfiguration.html'],
}


@resource_check('AWS::SecurityHub::SecurityControl', 'AWS::SecurityHub::ConfigurationPolicy')
def evaluate_securityhub_custom_values(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type in ('AWS::SecurityHub::SecurityControl','AWS::SecurityHub::ConfigurationPolicy'):
  policy=resource.type.endswith('::ConfigurationPolicy')
  pattern='/properties/ConfigurationPolicy/SecurityHub/SecurityControlsConfiguration/SecurityControlCustomParameters/*/Parameters' if policy else '/properties/Parameters'
  for base in expand(ctx,resource,pattern):
   for p in map_paths(ctx,resource,base):
    mode=get(p+'/ValueType');raw=get(p+'/Value');v='NEEDS_REVIEW'
    if mode=='DEFAULT':v='NOT_APPLICABLE'
    elif mode=='CUSTOM':v='FAIL' if raw is ABSENT or raw=={} else 'PASS' if isinstance(raw,dict) and raw else 'NEEDS_REVIEW'
    emit('SECURITYHUB_POLICY_CUSTOM_VALUE' if policy else 'SECURITYHUB_CONTROL_CUSTOM_VALUE',p,v,'CUSTOM needs a nonempty Value object; DEFAULT values are ignored, not rejected; escaped keys, unknown presence and actual member values remain separate')
 return results
