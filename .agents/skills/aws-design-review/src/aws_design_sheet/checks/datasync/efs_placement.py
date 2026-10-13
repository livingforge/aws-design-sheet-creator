"""DataSync EFS subnet placement supported by explicit mount targets."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved
from ..common.vpc_identity import vpc_identity

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'DATASYNC_EFS_SUBNET_PLACEMENT':[CF+'aws-properties-datasync-locationefs-ec2config.html',CF+'aws-resource-efs-mounttarget.html',CF+'aws-resource-ec2-subnet.html','https://docs.aws.amazon.com/efs/latest/ug/how-it-works.html']}


def explicit(ctx,r,path,kind):
    if not resolved(r):return None
    other=linked(ctx,r,path,kind)
    if not resolved(other):return None
    raw=read(ctx,r,path)
    if raw is not ABSENT and not literal(raw):return None
    if literal(raw) and raw.startswith('arn:'):
        service,resource={'AWS::EC2::Subnet':('ec2','subnet'), 'AWS::EFS::FileSystem':('elasticfilesystem','file-system')}[kind]
        m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:'+service+r':([a-z0-9-]+):([0-9]{12}):'+resource+r'/[a-zA-Z0-9-]+',raw)
        if not m or (m[1],m[2])!=(other.scope.region,other.scope.account):return None
    return other


def same_zone(ctx,a,b):
    if a is b:return True
    answers=[]
    for prop,pattern in [('AvailabilityZone',re.escape(a.scope.region)+r'[a-z]'),('AvailabilityZoneId',r'[a-z0-9]+-az[0-9]+')]:
        x,y=(value(ctx,r,'/properties/'+prop) for r in (a,b))
        if all(literal(v) and re.fullmatch(pattern,v) for v in (x,y)):answers.append(x==y)
    # Contradictory name/ID evidence does not establish a match.
    return True if answers and all(answers) else None


def placement(ctx,r):
    subnet=explicit(ctx,r,'/properties/Ec2Config/SubnetArn','AWS::EC2::Subnet')
    fs=explicit(ctx,r,'/properties/EfsFilesystemArn','AWS::EFS::FileSystem')
    if subnet is None or fs is None:return 'NEEDS_REVIEW'
    own=vpc_identity(ctx,subnet);match=False
    for mount in ctx.design.resources:
        if mount.type!='AWS::EFS::MountTarget':continue
        if explicit(ctx,mount,'/properties/FileSystemId',fs.type) is not fs:continue
        peer=explicit(ctx,mount,'/properties/SubnetId',subnet.type)
        if peer is None:continue
        other=vpc_identity(ctx,peer)
        if own is not None and other is not None and own[0]==other[0] and own!=other:return 'FAIL'
        same_vpc=peer is subnet or (own is not None and own==other)
        if same_vpc and same_zone(ctx,subnet,peer):match=True
    # No matching declared mount target does not prove that no external target exists.
    return 'PASS' if match else 'NEEDS_REVIEW'


@resource_check('AWS::DataSync::LocationEFS')
def evaluate_datasync_efs_placement(design,resource):
    if resource.type!='AWS::DataSync::LocationEFS':return []
    ctx=_Context(design,resource)
    f=ctx.finding('DATASYNC_EFS_SUBNET_PLACEMENT','/properties/Ec2Config/SubnetArn',placement(ctx,resource),'DataSync subnet must share the EFS mount-target VPC and the AZ of at least one target; it need not be the same subnet. An explicit different VPC fails because one file system has mount targets in only one VPC. Unlisted external targets, conditional references and unavailable AZ name/ID mappings remain reviewable. PASS only establishes declared placement, not network reachability.')
    f['source_checked_at']='2026-10-04';return [f]
