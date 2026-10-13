"""GameLift Streams declared VPC ownership and positive CIDR containment."""
from ipaddress import ip_network
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={rule:[CF+'aws-properties-gameliftstreams-streamgroup-vpctransitconfiguration.html',CF+'aws-resource-ec2-vpc.html',CF+'aws-resource-ec2-vpccidrblock.html'] for rule in ('GAMELIFT_STREAMS_VPC_ACCOUNT','GAMELIFT_STREAMS_VPC_CIDR_SUBSET')}


def explicit_vpc(ctx,r,path):
    if not resolved(r) or read(ctx,r,path) is not ABSENT:return None
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if len(refs)!=1 or refs[0].condition:return None
    targets=[node for node in ctx.design.resources if node.id==refs[0].target_resource_id and node.type=='AWS::EC2::VPC']
    if len(targets)!=1 or not resolved(targets[0]) or targets[0].scope.environment!=r.scope.environment:return None
    ctx.evidence.extend(refs[0].evidence_ids)
    return targets[0]


def network(text):
    if not literal(text):return None
    try:
        parsed=ip_network(text,strict=True)
        return parsed if parsed.version==4 else None
    except ValueError:return None


def containment(ctx,r,path,vpc):
    if vpc is None or vpc.scope.account!=r.scope.account:return 'NEEDS_REVIEW'
    location=value(ctx,r,path.rsplit('/',1)[0]+'/LocationName')
    if location!=vpc.scope.region:return 'NEEDS_REVIEW'
    blocks=[network(value(ctx,vpc,'/properties/CidrBlock'))]
    for other in ctx.design.resources:
        if other.type!='AWS::EC2::VPCCidrBlock' or not resolved(other):continue
        if read(ctx,other,'/properties/VpcId') is not ABSENT:continue
        if linked(ctx,other,'/properties/VpcId','AWS::EC2::VPC') is vpc:
            blocks.append(network(value(ctx,other,'/properties/CidrBlock')))
    raw=value(ctx,r,path+'/Ipv4CidrBlocks')
    if not isinstance(raw,list) or not 1<=len(raw)<=5:return 'NEEDS_REVIEW'
    wanted=[network(value(ctx,r,path+f'/Ipv4CidrBlocks/{i}')) for i in range(len(raw))]
    # Outside the declared ranges may still be in an unlisted secondary range.
    return 'PASS' if all(n is not None and any(b is not None and n.subnet_of(b) for b in blocks) for n in wanted) else 'NEEDS_REVIEW'


@resource_check('AWS::GameLiftStreams::StreamGroup')
def evaluate_gameliftstreams_vpc_cidrs(design,resource):
    if resource.type!='AWS::GameLiftStreams::StreamGroup':return []
    ctx=_Context(design,resource);out=[]
    for path in expand(ctx,resource,'/properties/LocationConfigurations/*/VpcTransitConfiguration'):
        vpc=explicit_vpc(ctx,resource,path+'/VpcId') if path.count('/')==4 else None
        account=('PASS' if vpc.scope.account==resource.scope.account else 'FAIL') if vpc else 'NEEDS_REVIEW'
        subset=containment(ctx,resource,path,vpc)
        for rule,verdict in [('GAMELIFT_STREAMS_VPC_ACCOUNT',account),('GAMELIFT_STREAMS_VPC_CIDR_SUBSET',subset)]:
            f=ctx.finding(rule,path,verdict,'Resolve an explicit VPC relation and require the stream-group account. CIDR PASS proves every requested IPv4 network is inside a declared primary or secondary VPC CIDR in the configured location. Missing secondary CIDRs cannot establish failure. Unknown identities, IPAM ranges and conditional references remain reviewable. Service-managed VPC overlap and live routing require external evidence.')
            f['source_checked_at']='2026-10-04';out.append(f)
    return out
