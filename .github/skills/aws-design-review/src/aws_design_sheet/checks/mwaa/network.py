"""Checks for AWS::MWAA::Environment."""
import re
from ipaddress import ip_network
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import literal
from ..common.subnet_zones import explicit, zones
from ..common.vpc_identity import vpc_identity

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={rule:[CF+'aws-properties-mwaa-environment-networkconfiguration.html','https://docs.aws.amazon.com/mwaa/latest/userguide/networking-about.html'] for rule in ('MWAA_NETWORK_VPC','MWAA_SUBNET_AZ_DIVERSITY','MWAA_PRIVATE_SUBNET_ROUTE')}


def subnet_pair(ctx,r):
    raw=value(ctx,r,'/properties/NetworkConfiguration/SubnetIds')
    if not isinstance(raw,list) or len(raw)!=2:return []
    return [explicit(ctx,r,f'/properties/NetworkConfiguration/SubnetIds/{i}','AWS::EC2::Subnet') for i in range(2)]


def vpcs(ctx,r,subnets):
    raw=value(ctx,r,'/properties/NetworkConfiguration/SecurityGroupIds')
    if len(subnets)!=2 or not isinstance(raw,list) or not 1<=len(raw)<=5:return 'NEEDS_REVIEW'
    groups=[explicit(ctx,r,f'/properties/NetworkConfiguration/SecurityGroupIds/{i}','AWS::EC2::SecurityGroup') for i in range(len(raw))]
    identities=[vpc_identity(ctx,node) for node in subnets+groups]
    known=[v for v in identities if v is not None]
    if any(a[0]==b[0] and a!=b for a in known for b in known):return 'FAIL'
    return 'PASS' if len(known)==len(identities) and len(set(known))==1 else 'NEEDS_REVIEW'


def public_route(ctx,subnet):
    if subnet is None:return False
    associations=[]
    for r in ctx.design.resources:
        if r.type=='AWS::EC2::SubnetRouteTableAssociation' and explicit(ctx,r,'/properties/SubnetId',subnet.type) is subnet:
            associations.append(explicit(ctx,r,'/properties/RouteTableId','AWS::EC2::RouteTable'))
    if len(associations)!=1 or associations[0] is None:return False
    table=associations[0]
    for route in ctx.design.resources:
        if route.type!='AWS::EC2::Route' or explicit(ctx,route,'/properties/RouteTableId',table.type) is not table:continue
        gateway=explicit(ctx,route,'/properties/GatewayId','AWS::EC2::InternetGateway')
        raw=value(ctx,route,'/properties/GatewayId')
        if gateway is None and not (literal(raw) and re.fullmatch(r'igw-[0-9a-f]+',raw)):continue
        for name,version in [('DestinationCidrBlock',4),('DestinationIpv6CidrBlock',6)]:
            cidr=value(ctx,route,'/properties/'+name)
            if not literal(cidr):continue
            try:
                if ip_network(cidr,strict=True).version==version:return True
            except ValueError:pass
    return False


@resource_check('AWS::MWAA::Environment')
def evaluate_mwaa_network(design,resource):
    if resource.type!='AWS::MWAA::Environment':return []
    ctx=_Context(design,resource);subnets=subnet_pair(ctx,resource)
    checks=[('MWAA_NETWORK_VPC',vpcs(ctx,resource,subnets),'Explicit subnet and security-group VPC identities must match.'),('MWAA_SUBNET_AZ_DIVERSITY',zones(ctx,subnets),'Two explicit subnets must occupy different AZs; contradictory AZ name/ID evidence is held.'),('MWAA_PRIVATE_SUBNET_ROUTE','FAIL' if any(public_route(ctx,s) for s in subnets) else 'NEEDS_REVIEW','An explicit associated route table with a direct Internet Gateway route violates private-subnet placement. NAT and egress-only gateways are not direct Internet Gateways. Missing routes cannot establish a private subnet because the inventory may be incomplete.')]
    out=[]
    for rule,verdict,reason in checks:
        f=ctx.finding(rule,'/properties/NetworkConfiguration',verdict,reason+' Unknown, conditional or external topology remains reviewable. No live reachability claim.')
        f['source_checked_at']='2026-10-04';out.append(f)
    return out
