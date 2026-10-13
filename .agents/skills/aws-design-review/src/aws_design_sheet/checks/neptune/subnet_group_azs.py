"""Checks for AWS::Neptune::DBSubnetGroup."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'NEPTUNE_SUBNET_GROUP_AZS': [CF+'aws-resource-neptune-dbsubnetgroup.html'],
}


def subnet_zones(ctx,resource):
    if not resolved(resource):return 'NEEDS_REVIEW'
    ids=value(ctx,resource,'/properties/SubnetIds')
    if not isinstance(ids,list) or not ids or len(ids)>1000:return 'NEEDS_REVIEW'
    zones=set()
    for i in range(len(ids)):
        subnet=linked(ctx,resource,'/properties/SubnetIds/'+str(i),'AWS::EC2::Subnet')
        if not resolved(subnet):return 'NEEDS_REVIEW'
        zone=value(ctx,subnet,'/properties/AvailabilityZone')
        if not literal(zone) or not re.fullmatch(re.escape(resource.scope.region)+r'[a-z]',zone):return 'NEEDS_REVIEW'
        zones.add(zone)
    return 'PASS' if len(zones)>=2 else 'FAIL'


@resource_check('AWS::Neptune::DBSubnetGroup')
def evaluate_neptune_subnet_group_azs(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::Neptune::DBSubnetGroup' and value(ctx,resource,'/properties/SubnetIds') is not ABSENT:
        emit('NEPTUNE_SUBNET_GROUP_AZS','/properties/SubnetIds',subnet_zones(ctx,resource),'all uniquely linked same-account/Region subnets with explicit ordinary AZ names must span at least two AZs; unknown/default placement, AZ IDs, local zones, conditional links and actual availability remain held')
    return results
