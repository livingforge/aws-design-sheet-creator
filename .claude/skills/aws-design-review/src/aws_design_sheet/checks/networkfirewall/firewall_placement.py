"""Network Firewall subnet VPC/AZ and transit-gateway Region placement."""
import re
from itertools import combinations
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.logical_vpc_identity import identity
from ..common.scoped_resolution import resolved
from ..common.subnet_zones import explicit, zones

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={r:[CF+'aws-resource-networkfirewall-firewall.html',CF+'aws-properties-networkfirewall-firewall-availabilityzonemapping.html'] for r in ('NETWORK_FIREWALL_SUBNET_VPC','NETWORK_FIREWALL_SUBNET_AZ_DIVERSITY','NETWORK_FIREWALL_TRANSIT_AZ_REGION')}


def subnet_checks(ctx,r):
    rows=value(ctx,r,'/properties/SubnetMappings')
    if rows is ABSENT:return ['NOT_APPLICABLE']*2
    if not resolved(r) or not isinstance(rows,list) or not 1<=len(rows)<=100:return ['NEEDS_REVIEW']*2
    ss=[explicit(ctx,r,f'/properties/SubnetMappings/{i}/SubnetId','AWS::EC2::Subnet') for i in range(len(rows))]
    ids=[identity(ctx,s) for s in [r]+ss];known=[v for v in ids if v is not None]
    vpc='FAIL' if any(a[0]==b[0] and a!=b for a,b in combinations(known,2)) else 'PASS' if len(known)==len(ids) and len(set(known))==1 else 'NEEDS_REVIEW'
    answers=[zones(ctx,list(pair)) for pair in combinations(ss,2)]
    az='FAIL' if 'FAIL' in answers else 'NEEDS_REVIEW' if any(s is None for s in ss) or 'NEEDS_REVIEW' in answers else 'PASS'
    return [vpc,az]


def transit_region(ctx,r):
    rows=value(ctx,r,'/properties/AvailabilityZoneMappings')
    if rows is ABSENT:return 'NOT_APPLICABLE'
    if not resolved(r) or not isinstance(rows,list) or not 1<=len(rows)<=100:return 'NEEDS_REVIEW'
    if read(ctx,r,'/properties/TransitGatewayId') is not ABSENT:return 'NEEDS_REVIEW'
    t=linked(ctx,r,'/properties/TransitGatewayId','AWS::EC2::TransitGateway')
    if not resolved(t):return 'NEEDS_REVIEW'
    pending=False
    for i in range(len(rows)):
        az=value(ctx,r,f'/properties/AvailabilityZoneMappings/{i}/AvailabilityZone')
        match=re.fullmatch(r'([a-z]{2}(?:-[a-z]+)+-\d+)[a-z]',az) if isinstance(az,str) else None
        if match is None:pending=True
        elif match[1]!=t.scope.region:return 'FAIL'
    return 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::NetworkFirewall::Firewall')
def evaluate_networkfirewall_firewall_placement(design,resource):
    if resource.type!='AWS::NetworkFirewall::Firewall':return []
    ctx=_Context(design,resource);vpc,az=subnet_checks(ctx,resource)
    out=[]
    checks=[('NETWORK_FIREWALL_SUBNET_VPC','SubnetMappings',vpc,'All primary subnets belong to the firewall VPC.'),('NETWORK_FIREWALL_SUBNET_AZ_DIVERSITY','SubnetMappings',az,'Every pair of primary subnets uses a different AZ.'),('NETWORK_FIREWALL_TRANSIT_AZ_REGION','AvailabilityZoneMappings',transit_region(ctx,resource),'Ordinary AZ names must belong to the explicitly referenced transit gateway Region; AZ IDs and extended zone names need external mapping.')]
    for rule,path,verdict,reason in checks:
        f=ctx.finding(rule,'/properties/'+path,verdict,reason+' Conditional, unresolved or external references remain reviewable. PASS concerns declared placement only, not capacity or reachability.')
        f['source_checked_at']='2026-10-04';out.append(f)
    return out
