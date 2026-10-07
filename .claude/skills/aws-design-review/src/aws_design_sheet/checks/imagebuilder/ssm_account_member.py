"""Checks for AWS::ImageBuilder::DistributionConfiguration."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'IMAGEBUILDER_SSM_ACCOUNT_MEMBER': [CF+'aws-properties-imagebuilder-distributionconfiguration-ssmparameterconfiguration.html'],
}


@resource_check('AWS::ImageBuilder::DistributionConfiguration')
def evaluate_imagebuilder_ssm_account_member(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::ImageBuilder::DistributionConfiguration':
  for base in expand(ctx,resource,'/properties/Distributions/*'):
   path=base+'/AmiDistributionConfiguration/TargetAccountIds';raw=get(path)
   names=[get(path+'/'+str(i)) for i in range(len(raw))] if isinstance(raw,list) else []
   for p in expand(ctx,resource,base+'/SsmParameterConfigurations/*/AmiAccountId'):
    account=get(p);v='NEEDS_REVIEW'
    if literal(account) and isinstance(raw,list):v='PASS' if account in [x for x in names if literal(x)] else 'FAIL' if all(literal(x) for x in names) else 'NEEDS_REVIEW'
    emit('IMAGEBUILDER_SSM_ACCOUNT_MEMBER',p,v,'explicit AmiAccountId must occur in same distribution target accounts; omitted account/default target ownership and unresolved lists held')
 return results
