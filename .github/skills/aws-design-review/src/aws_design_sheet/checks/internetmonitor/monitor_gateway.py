"""Existential Internet Gateway attachment proof for VPC-only monitor additions."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'INTERNET_MONITOR_VPC_GATEWAY':[CF+'aws-resource-internetmonitor-monitor.html',CF+'aws-resource-ec2-vpcgatewayattachment.html']}


def check(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    raw=value(ctx,r,'/properties/ResourcesToAdd')
    if raw is ABSENT or raw==[]:return 'NOT_APPLICABLE'
    if not isinstance(raw,list) or len(raw)>2048:return 'NEEDS_REVIEW'
    if value(ctx,r,'/properties/Resources') not in (ABSENT,[]) or value(ctx,r,'/properties/ResourcesToRemove') not in (ABSENT,[]):return 'NEEDS_REVIEW'
    if value(ctx,r,'/properties/IncludeLinkedAccounts') is True or value(ctx,r,'/properties/LinkedAccountId') is not ABSENT:return 'NEEDS_REVIEW'
    vpcs=[];pending=False
    for i in range(len(raw)):
        path=f'/properties/ResourcesToAdd/{i}';arn=read(ctx,r,path)
        m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:ec2:([a-z0-9-]+):([0-9]{12}):vpc/(vpc-[0-9a-f]+)',arn) if literal(arn) else None
        if not m:
            if literal(arn) and re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:(?:cloudfront::[0-9]{12}:distribution/[A-Z0-9]+|workspaces:[a-z0-9-]+:[0-9]{12}:directory/[a-zA-Z0-9-]+|elasticloadbalancing:[a-z0-9-]+:[0-9]{12}:loadbalancer/net/[^/]+/[a-z0-9]+)',arn):return 'NOT_APPLICABLE'
            pending=True;continue
        vpc=linked(ctx,r,path,'AWS::EC2::VPC')
        if resolved(vpc) and (vpc.scope.region,vpc.scope.account)==(m[1],m[2]):vpcs.append(vpc)
        else:pending=True
    if pending:return 'NEEDS_REVIEW'
    for vpc in vpcs:
        for attachment in ctx.design.resources:
            if attachment.type!='AWS::EC2::VPCGatewayAttachment' or not resolved(attachment):continue
            if linked(ctx,attachment,'/properties/VpcId',vpc.type) is not vpc:continue
            if value(ctx,attachment,'/properties/VpnGatewayId') is not ABSENT:continue
            gateway=linked(ctx,attachment,'/properties/InternetGatewayId','AWS::EC2::InternetGateway')
            raw=value(ctx,attachment,'/properties/InternetGatewayId')
            if resolved(gateway) or (literal(raw) and re.fullmatch(r'igw-[0-9a-f]+',raw)):return 'PASS'
    return 'NEEDS_REVIEW'


@resource_check('AWS::InternetMonitor::Monitor')
def evaluate_internetmonitor_monitor_gateway(design,resource):
    if resource.type!='AWS::InternetMonitor::Monitor':return []
    ctx=_Context(design,resource)
    f=ctx.finding('INTERNET_MONITOR_VPC_GATEWAY','/properties/ResourcesToAdd',check(ctx,resource),'VPC-only monitor additions require at least one selected VPC with an Internet Gateway attachment. PASS proves a declared explicit attachment, not live internet connectivity. A missing attachment in an incomplete inventory is not a failure. Cross-account observability, update/removal combinations, unresolved ARNs and conditional links remain reviewable; VPN and egress-only gateways do not establish this condition.')
    f['source_checked_at']='2026-10-04';return [f]
