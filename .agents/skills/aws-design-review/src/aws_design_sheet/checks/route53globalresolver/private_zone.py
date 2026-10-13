"""Checks for AWS::Route53GlobalResolver::HostedZoneAssociation."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'GLOBALRESOLVER_PRIVATE_ZONE': [CF+'aws-resource-route53globalresolver-hostedzoneassociation.html',CF+'aws-resource-route53-hostedzone.html'],
}


def private_zone(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    zone=linked(ctx,r,'/properties/HostedZoneId','AWS::Route53::HostedZone')
    if not resolved(zone):return 'NEEDS_REVIEW'
    vpcs=value(ctx,zone,'/properties/VPCs')
    if not isinstance(vpcs,list) or not vpcs:return 'NEEDS_REVIEW'
    for i in range(len(vpcs)):
        base='/properties/VPCs/'+str(i)
        if not literal(value(ctx,zone,base+'/VPCId')) or not literal(value(ctx,zone,base+'/VPCRegion')):return 'NEEDS_REVIEW'
    return 'PASS'


@resource_check('AWS::Route53GlobalResolver::HostedZoneAssociation')
def evaluate_route53globalresolver_private_zone(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Route53GlobalResolver::HostedZoneAssociation' and value(ctx,resource,'/properties/HostedZoneId') is not ABSENT:
        emit('GLOBALRESOLVER_PRIVATE_ZONE','/properties/HostedZoneId',private_zone(ctx,resource),'explicit linked zone with known nonempty VPC configuration establishes private-zone intent; omitted/unknown VPCs, external zones, Region support and deployed associations remain held')
    return results
