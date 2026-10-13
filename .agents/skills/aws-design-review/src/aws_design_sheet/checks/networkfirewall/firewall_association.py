"""Association AZ coverage from a declared firewall's primary subnet mappings."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.scoped_resolution import resolved
from ..common.subnet_zones import explicit, zones

SOURCES={'NETWORK_FIREWALL_ASSOCIATION_AZ':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-networkfirewall-vpcendpointassociation.html']}


def coverage(ctx,r):
    if not resolved(r) or read(ctx,r,'/properties/FirewallArn') is not ABSENT:return 'NEEDS_REVIEW'
    fw=linked(ctx,r,'/properties/FirewallArn','AWS::NetworkFirewall::Firewall')
    subnet=explicit(ctx,r,'/properties/SubnetMapping/SubnetId','AWS::EC2::Subnet')
    if not resolved(fw) or subnet is None:return 'NEEDS_REVIEW'
    rows=value(ctx,fw,'/properties/SubnetMappings')
    if not isinstance(rows,list) or not 1<=len(rows)<=100:return 'NEEDS_REVIEW'
    pending=False
    for i in range(len(rows)):
        other=explicit(ctx,fw,f'/properties/SubnetMappings/{i}/SubnetId','AWS::EC2::Subnet')
        # The existing helper reports FAIL for identical AZs (diversity check).
        result=zones(ctx,[subnet,other])
        if result=='FAIL':return 'PASS'
        if result=='NEEDS_REVIEW':pending=True
    return 'NEEDS_REVIEW' if pending else 'FAIL'


@resource_check('AWS::NetworkFirewall::VpcEndpointAssociation')
def evaluate_networkfirewall_firewall_association(design,resource):
    if resource.type!='AWS::NetworkFirewall::VpcEndpointAssociation':return []
    ctx=_Context(design,resource)
    f=ctx.finding('NETWORK_FIREWALL_ASSOCIATION_AZ','/properties/SubnetMapping',coverage(ctx,resource),'The association subnet AZ must occur in the referenced firewall primary SubnetMappings. Different VPCs are allowed. Comparison uses resolved references within one account and Region; cross-account AZ names, incomplete mappings, contradictory AZ evidence and literal firewall ARNs remain reviewable. PASS establishes declared AZ coverage, not existing endpoint readiness or sharing permissions.')
    f['source_checked_at']='2026-10-04';return [f]
