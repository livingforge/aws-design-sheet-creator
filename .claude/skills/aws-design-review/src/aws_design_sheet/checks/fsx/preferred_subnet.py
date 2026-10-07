"""Checks for AWS::FSx::FileSystem."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.string_lists import strings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'FSX_PREFERRED_SUBNET': [CF+'aws-resource-fsx-filesystem.html'],
}


@resource_check('AWS::FSx::FileSystem')
def evaluate_fsx_preferred_subnet(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::FSx::FileSystem':
        subnets,pending=strings(ctx,resource,'/properties/SubnetIds')
        for owner in ('WindowsConfiguration','OntapConfiguration','OpenZFSConfiguration'):
            path='/properties/'+owner+'/PreferredSubnetId';preferred=value(ctx,resource,path)
            if preferred is ABSENT:continue
            deployment=value(ctx,resource,'/properties/'+owner+'/DeploymentType')
            applicable=owner in ('WindowsConfiguration','OntapConfiguration') and deployment=='MULTI_AZ_1'
            verdict='NEEDS_REVIEW'
            if applicable and literal(preferred):verdict='PASS' if preferred in subnets else 'NEEDS_REVIEW' if pending else 'FAIL'
            emit('FSX_PREFERRED_SUBNET',path,verdict,'explicit Windows/ONTAP MULTI_AZ_1 preferred subnet must occur in SubnetIds; other deployments, OpenZFS, unresolved aliases and actual subnet state remain under review')
    return results
