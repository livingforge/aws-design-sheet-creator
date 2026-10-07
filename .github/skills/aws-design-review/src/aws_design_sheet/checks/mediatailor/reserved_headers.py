"""Checks for AWS::MediaTailor::Function."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES = {
    'MEDIATAILOR_RESERVED_HEADERS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-mediatailor-function-vastrequestconfiguration.html',
    ],
}


@resource_check('AWS::MediaTailor::Function')
def evaluate_mediatailor_reserved_headers(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::MediaTailor::Function':
  p='/properties/VastRequestConfiguration/Headers';raw=get(p)
  if raw is not ABSENT:
   pending=not isinstance(raw,dict);invalid=False
   for key in raw if isinstance(raw,dict) else ():
    if not literal(key) or '{%' in key:pending=True
    elif key.lower().startswith('x-amz-'):invalid=True
   emit('MEDIATAILOR_RESERVED_HEADERS',p,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','rejects explicit X-Amz- reserved header prefix case-insensitively; method-override header catalog and output binding directive validation remain held')
 return results
