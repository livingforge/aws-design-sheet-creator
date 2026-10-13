"""Checks for AWS::EMR::Studio."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand
from ..common.scoped_resolution import resolved

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EMR_STUDIO_VPC_LINKS': [CF+'aws-resource-emr-studio.html'],
}


@resource_check('AWS::EMR::Studio')
def evaluate_emr_studio_vpc_links(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::EMR::Studio':
        vpc = linked(ctx,resource,'/properties/VpcId','AWS::EC2::VPC')
        paths = [(p,'AWS::EC2::Subnet') for p in expand(ctx,resource,'/properties/SubnetIds/*')]
        paths += [('/properties/'+field,'AWS::EC2::SecurityGroup') for field in ('EngineSecurityGroupId','WorkspaceSecurityGroupId') if value(ctx,resource,'/properties/'+field) is not ABSENT]
        for path,kind in paths:
            member = linked(ctx,resource,path,kind)
            owner = linked(ctx,member,'/properties/VpcId','AWS::EC2::VPC') if member else None
            verdict = 'NEEDS_REVIEW' if not all(resolved(r) for r in (resource,member,vpc,owner)) else 'PASS' if vpc.id==owner.id else 'FAIL'
            emit('EMR_STUDIO_VPC_LINKS',path,verdict,'studio and each explicit subnet/security group must link uniquely to the same VPC identity; unresolved/default/external members, reachability and deployed state remain held')
    return results
