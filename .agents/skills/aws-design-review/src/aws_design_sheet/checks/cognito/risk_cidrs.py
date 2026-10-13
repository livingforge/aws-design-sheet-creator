"""Checks for AWS::Cognito::UserPoolRiskConfigurationAttachment."""
import ipaddress
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

SOURCES = {
    'COGNITO_RISK_CIDRS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cognito-userpoolriskconfigurationattachment-riskexceptionconfigurationtype.html',
    ],
}


@resource_check('AWS::Cognito::UserPoolRiskConfigurationAttachment')
def evaluate_cognito_risk_cidrs(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::Cognito::UserPoolRiskConfigurationAttachment':
  for key in ('BlockedIPRangeList','SkippedIPRangeList'):
   for p in expand(ctx,resource,'/properties/RiskExceptionConfiguration/'+key+'/*'):
    raw=get(p);v='NEEDS_REVIEW'
    if literal(raw) and '%' not in raw:
     try:
      if '/' not in raw:raise ValueError('prefix required')
      ipaddress.ip_network(raw,strict=False);v='PASS'
     except ValueError:v='FAIL'
    emit('COGNITO_RISK_CIDRS',p,v,'explicit IP range requires CIDR notation; host bits are accepted for notation only; unresolved/scoped text held; actual risk policy effect is separate')
 return results
