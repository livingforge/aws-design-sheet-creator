"""Checks for AWS::Synthetics::Canary."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SYNTHETICS_ENV_KEYS': [CF+'aws-properties-synthetics-canary-runconfig.html'],
}


@resource_check('AWS::Synthetics::Canary')
def evaluate_synthetics_env_keys(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::Synthetics::Canary':
  p='/properties/RunConfig/EnvironmentVariables';raw=get(p)
  if raw is not ABSENT:
   invalid=False;pending=not isinstance(raw,dict)
   for key in raw if isinstance(raw,dict) else ():
    if not literal(key):pending=True
    elif not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]+',key):invalid=True
   emit('SYNTHETICS_ENV_KEYS',p,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','explicit environment keys match the documented ASCII letter, digit and underscore pattern with at least two characters; Lambda reserved-key catalog and 4KB serialization accounting remain unverified')
 return results
