"""Checks for AWS::WorkSpacesWeb::NetworkSettings."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'WORKSPACESWEB_SUBNET_AZ_DIVERSITY': [CF+'aws-resource-workspacesweb-networksettings.html','https://docs.aws.amazon.com/ram/latest/userguide/working-with-az-ids.html'],
}


def subnet_diversity(ctx,r):
    raw=value(ctx,r,'/properties/SubnetIds')
    if not resolved(r) or not isinstance(raw,list) or not 2<=len(raw)<=1000:return 'NEEDS_REVIEW'
    zones=[];zone_ids=[];pairs=[];pending=False
    for i in range(len(raw)):
        subnet=linked(ctx,r,'/properties/SubnetIds/'+str(i),'AWS::EC2::Subnet')
        if not resolved(subnet):pending=True;continue
        az=value(ctx,subnet,'/properties/AvailabilityZone')
        azid=value(ctx,subnet,'/properties/AvailabilityZoneId')
        name=az if literal(az) and re.fullmatch(re.escape(r.scope.region)+r'[a-z]',az) else None
        identity=azid if literal(azid) and re.fullmatch(r'[a-z0-9]+-az[0-9]+',azid) else None
        if name:zones.append(name)
        if identity:zone_ids.append(identity)
        if name and identity:pairs.append((name,identity))
        if name is None and identity is None:pending=True
    # Supplied name/ID mappings must be internally consistent before using them.
    if any(len({b for a,b in pairs if a==name})>1 for name in zones) or any(len({a for a,b in pairs if b==identity})>1 for identity in zone_ids):return 'NEEDS_REVIEW'
    if len(set(zones))>=2 or len(set(zone_ids))>=2:return 'PASS'
    if not pending and (len(zones)==len(raw) or len(zone_ids)==len(raw)):return 'FAIL'
    if not pending and pairs and len(zones)+len(zone_ids)-len(pairs)==len(raw):return 'FAIL'
    return 'NEEDS_REVIEW'


@resource_check('AWS::WorkSpacesWeb::NetworkSettings')
def evaluate_workspacesweb_subnet_az_diversity(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::WorkSpacesWeb::NetworkSettings' and value(ctx,resource,'/properties/SubnetIds') is not ABSENT:
        emit('WORKSPACESWEB_SUBNET_AZ_DIVERSITY','/properties/SubnetIds',subnet_diversity(ctx,resource),'two distinct explicit AZ names or IDs on linked subnets establish diversity; mixed incomparable identities, contradictory name/ID evidence, local zones, external links and service availability remain held')
    return results
