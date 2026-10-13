"""Checks for AWS::InternetMonitor::Monitor."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES = {
    'INTERNETMONITOR_RESOURCE_FAMILY': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-internetmonitor-monitor.html',
    ],
}


@resource_check('AWS::InternetMonitor::Monitor')
def evaluate_internetmonitor_resource_family(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::InternetMonitor::Monitor':
  p='/properties/ResourcesToAdd';raw=get(p)
  if raw is not ABSENT:
   families=set();pending=not isinstance(raw,list)
   for i in range(len(raw)) if isinstance(raw,list) else ():
    arn=get(p+'/'+str(i));family=None
    if literal(arn):
     if re.fullmatch(r'arn:[^:]+:ec2:[^:]+:[0-9]{12}:vpc/vpc-[a-z0-9]+',arn):family='combined'
     elif re.fullmatch(r'arn:[^:]+:cloudfront::[0-9]{12}:distribution/[A-Za-z0-9]+',arn):family='combined'
     elif re.fullmatch(r'arn:[^:]+:elasticloadbalancing:[^:]+:[0-9]{12}:loadbalancer/net/[^/]+/[a-z0-9]+',arn):family='nlb'
     elif re.fullmatch(r'arn:[^:]+:workspaces:[^:]+:[0-9]{12}:directory/[^/]+',arn):family='workspaces'
    if family:families.add(family)
    else:pending=True
   emit('INTERNETMONITOR_RESOURCE_FAMILY',p,'FAIL' if len(families)>1 else 'NEEDS_REVIEW' if pending else 'PASS','ResourcesToAdd may mix VPC/CloudFront but not NLB or WorkSpaces with another family; unknown ARN forms and actual connectivity held')
 return results
