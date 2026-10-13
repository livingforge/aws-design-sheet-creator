"""Checks for AWS::DataSync::Task."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES = {
    'DATASYNC_RATE_INTERVAL': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-datasync-task-taskschedule.html',
    ],
}


@resource_check('AWS::DataSync::Task')
def evaluate_datasync_task_rate_interval(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::DataSync::Task':
  p='/properties/Schedule/ScheduleExpression';raw=get(p)
  if raw is not ABSENT:
   m=re.fullmatch(r'rate\(([1-9][0-9]*) (minute|minutes|hour|hours|day|days)\)',raw) if literal(raw) else None
   v='NEEDS_REVIEW'
   if m:v='PASS' if int(m[1])*({'minute':1,'hour':60,'day':1440}[m[2].rstrip('s')])>=60 else 'FAIL'
   emit('DATASYNC_RATE_INTERVAL',p,v,'explicit rate interval is at least sixty minutes; cron calendar evaluation and unsupported expression forms remain held')
 return results
