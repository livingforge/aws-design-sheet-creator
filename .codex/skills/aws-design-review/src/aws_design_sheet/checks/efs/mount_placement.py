"""Checks for AWS::EFS::MountTarget."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.scoped_resolution import resolved
from ..common.vpc_identity import vpc_identity

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={rule:[CF+'aws-resource-efs-mounttarget.html',CF+'aws-resource-efs-filesystem.html',CF+'aws-resource-ec2-subnet.html',CF+'aws-resource-ec2-securitygroup.html'] for rule in ('EFS_MOUNT_SECURITY_GROUP_VPC','EFS_MOUNT_ONE_ZONE_SUBNET')}


def placement(ctx,r,subnet):
    if not resolved(r) or not resolved(subnet):return 'NEEDS_REVIEW'
    own=vpc_identity(ctx,subnet);raw=value(ctx,r,'/properties/SecurityGroups')
    if own is None or not isinstance(raw,list) or not 0<len(raw)<=100:return 'NEEDS_REVIEW'
    pending=False
    for i in range(len(raw)):
        group=linked(ctx,r,'/properties/SecurityGroups/'+str(i),'AWS::EC2::SecurityGroup')
        other=vpc_identity(ctx,group)
        if other is None or other[0]!=own[0]:pending=True
        elif other!=own:return 'FAIL'
    return 'NEEDS_REVIEW' if pending else 'PASS'


def zone(ctx,r,subnet):
    filesystem=linked(ctx,r,'/properties/FileSystemId','AWS::EFS::FileSystem')
    if not all(resolved(x) for x in (r,filesystem,subnet)):return 'NEEDS_REVIEW'
    a=value(ctx,filesystem,'/properties/AvailabilityZoneName')
    b=value(ctx,subnet,'/properties/AvailabilityZone')
    if not all(isinstance(x,str) and re.fullmatch(re.escape(r.scope.region)+r'[a-z]',x) for x in (a,b)):return 'NEEDS_REVIEW'
    return 'PASS' if a==b else 'FAIL'


@resource_check('AWS::EFS::MountTarget')
def evaluate_efs_mount_placement(design,resource):
    if resource.type!='AWS::EFS::MountTarget':return []
    ctx=_Context(design,resource);subnet=linked(ctx,resource,'/properties/SubnetId','AWS::EC2::Subnet')
    results=[]
    for rule,path,verdict in [('EFS_MOUNT_SECURITY_GROUP_VPC','/properties/SecurityGroups',placement(ctx,resource,subnet)),('EFS_MOUNT_ONE_ZONE_SUBNET','/properties/SubnetId',zone(ctx,resource,subnet))]:
        f=ctx.finding(rule,path,verdict,'Explicit security groups must share the subnet VPC. A One Zone file system and mount subnet must share an Availability Zone. Unknown/default configuration, conditional references, incomparable VPC identities and unavailable AZ name/ID mappings remain reviewable; network reachability is separate.')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
