"""Checks for AWS::SageMaker::NotebookInstance."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SAGEMAKER_NOTEBOOK_SECURITY_VPC': [CF+'aws-resource-sagemaker-notebookinstance.html'],
}


def security_vpc(ctx,r,path):
    if not resolved(r):return 'NEEDS_REVIEW'
    subnet=linked(ctx,r,'/properties/SubnetId','AWS::EC2::Subnet')
    group=linked(ctx,r,path,'AWS::EC2::SecurityGroup')
    if not resolved(subnet) or not resolved(group):return 'NEEDS_REVIEW'
    owners=[value(ctx,x,'/properties/VpcId') for x in (subnet,group)]
    if not all(literal(x) and re.fullmatch(r'vpc-(?:[0-9a-f]{8}|[0-9a-f]{17})',x) for x in owners):return 'NEEDS_REVIEW'
    return 'PASS' if owners[0]==owners[1] else 'FAIL'


@resource_check('AWS::SageMaker::NotebookInstance')
def evaluate_sagemaker_notebook_hooks_and_vpc(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::SageMaker::NotebookInstance':
        for path in expand(ctx,resource,'/properties/SecurityGroupIds/*'):
            emit('SAGEMAKER_NOTEBOOK_SECURITY_VPC',path,security_vpc(ctx,resource,path),'linked subnet and security group explicit literal VPC IDs must match; unresolved VPC aliases/defaults, conditional/external links, effective network access and permissions remain held')
    return results
