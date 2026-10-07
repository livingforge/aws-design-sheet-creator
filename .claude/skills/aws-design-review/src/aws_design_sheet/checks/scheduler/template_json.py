"""Checks for AWS::Scheduler::Schedule."""
import json
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SCHEDULER_TEMPLATE_JSON': [CF+'aws-properties-scheduler-schedule-target.html'],
}


@resource_check('AWS::Scheduler::Schedule')
def evaluate_scheduler_template_json(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::Scheduler::Schedule':
  p='/properties/Target/Input';raw=get(p);arn=get('/properties/Target/Arn')
  if raw is not ABSENT:
   v='NEEDS_REVIEW'
   match=re.fullmatch(r'arn:(?:aws|aws-cn|aws-us-gov):(lambda|states|events):[^:]+:[0-9]{12}:(function|stateMachine|event-bus):?.*',arn) if literal(arn) else None
   if match and (match[1],match[2]) in (('lambda','function'),('states','stateMachine'),('events','event-bus')) and literal(raw):
    try:json.loads(raw,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('non-JSON constant')));v='PASS'
    except (ValueError,RecursionError):v='FAIL'
   emit('SCHEDULER_TEMPLATE_JSON',p,v,'explicit templated Lambda/StepFunctions/EventBridge target input must parse as JSON; universal/unknown targets and substitutions held; payload semantics separate')
 return results
