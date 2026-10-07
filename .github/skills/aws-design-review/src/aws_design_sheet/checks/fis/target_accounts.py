"""Explicit target-account coverage for multi-account experiment templates."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

SOURCES={'FIS_MULTI_ACCOUNT_CONFIG_COVERAGE':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-fis-targetaccountconfiguration.html','https://docs.aws.amazon.com/fis/latest/userguide/experiment-options.html','https://docs.aws.amazon.com/fis/latest/userguide/multi-account.html']}


def target_accounts(ctx,r):
    raw=value(ctx,r,'/properties/Targets')
    if not isinstance(raw,dict) or not 1<=len(raw)<=100:return None
    accounts=set()
    for name in raw:
        if not isinstance(name,str) or not re.fullmatch(r'[a-zA-Z0-9_-]+',name):return None
        base='/properties/Targets/'+name
        # Tag-selected accounts are defined by configurations rather than an
        # explicit ARN inventory, so this narrow coverage check holds them.
        tags=value(ctx,r,base+'/ResourceTags')
        if tags is not ABSENT and tags!={}:return None
        arns=value(ctx,r,base+'/ResourceArns')
        if not isinstance(arns,list) or not 1<=len(arns)<=100:return None
        for i in range(len(arns)):
            arn=value(ctx,r,base+f'/ResourceArns/{i}')
            match=re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):[a-z0-9-]+:([a-z0-9-]+):([0-9]{12}):[^\s*?]+',arn) if literal(arn) else None
            if not match or match[2]!=r.scope.region:return None
            accounts.add(match[3])
    return accounts


def coverage(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    mode=value(ctx,r,'/properties/ExperimentOptions/AccountTargeting')
    if mode=='single-account' or mode is ABSENT:return 'NOT_APPLICABLE'
    if mode!='multi-account':return 'NEEDS_REVIEW'
    wanted=target_accounts(ctx,r)
    if not wanted:return 'NEEDS_REVIEW'
    configured=set()
    for other in ctx.design.resources:
        if other.type!='AWS::FIS::TargetAccountConfiguration' or not resolved(other):continue
        path='/properties/ExperimentTemplateId'
        if read(ctx,other,path) is not ABSENT or linked(ctx,other,path,r.type) is not r:continue
        account=value(ctx,other,'/properties/AccountId');role=value(ctx,other,'/properties/RoleArn')
        if not literal(account) or not re.fullmatch('[0-9]{12}',account):continue
        match=re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+',role) if literal(role) else None
        if match and match[2]==account:configured.add(account)
    return 'PASS' if wanted<=configured else 'NEEDS_REVIEW'


@resource_check('AWS::FIS::ExperimentTemplate')
def evaluate_fis_target_accounts(design,resource):
    if resource.type!='AWS::FIS::ExperimentTemplate':return []
    ctx=_Context(design,resource)
    f=ctx.finding('FIS_MULTI_ACCOUNT_CONFIG_COVERAGE','/properties/ExperimentOptions/AccountTargeting',coverage(ctx,resource),'For explicit multi-account ARN targets, recognize one declared TargetAccountConfiguration per target account, with a matching IAM role account. Missing inventory never proves absence. Tag selection, external configurations, dynamic ARNs, unresolved role identities and conditional references remain reviewable. PASS covers declared account configuration only, not IAM permission or live experiment readiness.')
    f['source_checked_at']='2026-10-04';return [f]
