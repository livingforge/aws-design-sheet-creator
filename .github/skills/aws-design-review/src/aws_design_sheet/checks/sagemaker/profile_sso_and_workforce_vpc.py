"""Checks for AWS::SageMaker::UserProfile, AWS::SageMaker::Workforce."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SAGEMAKER_PROFILE_SSO_FIELDS': [CF+'aws-resource-sagemaker-userprofile.html',CF+'aws-resource-sagemaker-domain.html'],
    'SAGEMAKER_WORKFORCE_SECURITY_VPC': ['https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_WorkforceVpcConfigRequest.html'],
}


def sso_fields(ctx,r):
    domain=linked(ctx,r,'/properties/DomainId','AWS::SageMaker::Domain')
    if not resolved(r) or not resolved(domain):return 'NEEDS_REVIEW'
    mode=value(ctx,domain,'/properties/AuthMode')
    fields=[value(ctx,r,'/properties/'+key) for key in ('SingleSignOnUserIdentifier','SingleSignOnUserValue')]
    if mode=='SSO':
        if any(x is ABSENT for x in fields):return 'FAIL'
        return 'PASS' if all(literal(x) for x in fields) else 'NEEDS_REVIEW'
    if mode=='IAM':
        if any(literal(x) for x in fields):return 'FAIL'
        return 'PASS' if all(x is ABSENT for x in fields) else 'NEEDS_REVIEW'
    return 'NEEDS_REVIEW'


def workforce_vpc(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    owners=[]
    for key,kind in (('Subnets','AWS::EC2::Subnet'),('SecurityGroupIds','AWS::EC2::SecurityGroup')):
        path='/properties/WorkforceVpcConfig/'+key
        raw=value(ctx,r,path)
        if not isinstance(raw,list) or not raw:return 'NEEDS_REVIEW'
        for i in range(len(raw)):
            member=linked(ctx,r,path+'/'+str(i),kind)
            if not resolved(member):return 'NEEDS_REVIEW'
            owner=value(ctx,member,'/properties/VpcId')
            if not literal(owner) or not re.fullmatch(r'vpc-(?:[0-9a-f]{8}|[0-9a-f]{17})',owner):return 'NEEDS_REVIEW'
            owners.append(owner)
    return 'PASS' if len(set(owners))==1 else 'FAIL'


@resource_check('AWS::SageMaker::UserProfile', 'AWS::SageMaker::Workforce')
def evaluate_sagemaker_profile_sso_and_workforce_vpc(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::SageMaker::UserProfile' and value(ctx,resource,'/properties/DomainId') is not ABSENT:
        emit('SAGEMAKER_PROFILE_SSO_FIELDS','/properties/DomainId',sso_fields(ctx,resource),'linked Domain explicit SSO requires both identity fields; IAM prohibits them; unknown references and actual directory identity/assignment remain held')
    if resource.type=='AWS::SageMaker::Workforce' and value(ctx,resource,'/properties/WorkforceVpcConfig') is not ABSENT:
        emit('SAGEMAKER_WORKFORCE_SECURITY_VPC','/properties/WorkforceVpcConfig',workforce_vpc(ctx,resource),'all uniquely linked subnets and security groups must share an explicit literal VPC ID; defaults, VPC aliases, config VpcId identity, conditional/external links and actual connectivity remain held')
    return results
