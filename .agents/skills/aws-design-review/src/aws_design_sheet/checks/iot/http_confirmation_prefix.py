"""Checks for AWS::IoT::TopicRule."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'IOT_HTTP_CONFIRMATION_PREFIX': [CF+'aws-properties-iot-topicrule-httpaction.html'],
}


@resource_check('AWS::IoT::TopicRule')
def evaluate_iot_http_confirmation_prefix(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::IoT::TopicRule':
  for pattern in ('/properties/TopicRulePayload/Actions/*/Http','/properties/TopicRulePayload/ErrorAction/Http'):
   for p in expand(ctx,resource,pattern):
    prefix=get(p+'/ConfirmationUrl');url=get(p+'/Url')
    if prefix is ABSENT:continue
    v='PASS' if literal(prefix) and literal(url) and url.startswith(prefix) else 'FAIL' if literal(prefix) and literal(url) else 'NEEDS_REVIEW'
    emit('IOT_HTTP_CONFIRMATION_PREFIX',p+'/ConfirmationUrl',v,'explicit confirmation URL must be a literal prefix of endpoint URL; substitutions, URL syntax and destination authorization are separate')
 return results
