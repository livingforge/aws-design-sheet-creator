"""Checks for AWS::APS::Scraper."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APS_SCRAPER_VPC_ALIGNMENT': [CF+'aws-properties-aps-scraper-eksconfiguration.html'],
}


def scraper_vpc(ctx, r):
    base = '/properties/Source/EksConfiguration'
    cluster = linked(ctx, r, base+'/ClusterArn', 'AWS::EKS::Cluster')
    if not resolved(r) or not resolved(cluster):
        return 'NEEDS_REVIEW'
    members = [(cluster, '/properties/ResourcesVpcConfig/SubnetIds', 'AWS::EC2::Subnet'),
               (r, base+'/SubnetIds', 'AWS::EC2::Subnet')]
    security = value(ctx, r, base+'/SecurityGroupIds')
    if security is not ABSENT:
        members.append((r, base+'/SecurityGroupIds', 'AWS::EC2::SecurityGroup'))
    vpcs = []
    for source, path, kind in members:
        raw = value(ctx, source, path)
        if not isinstance(raw, list) or not raw:
            return 'NEEDS_REVIEW'
        for i in range(len(raw)):
            member = linked(ctx, source, path+'/'+str(i), kind)
            if not resolved(member):
                return 'NEEDS_REVIEW'
            vpc = value(ctx, member, '/properties/VpcId')
            if not literal(vpc):
                return 'NEEDS_REVIEW'
            vpcs.append(vpc)
    return 'PASS' if len(set(vpcs)) == 1 else 'FAIL'


@resource_check('AWS::APS::Scraper')
def evaluate_aps_scraper_vpc_alignment(design, resource):
    ctx = _Context(design, resource); results = []
    def emit(rule, path, verdict, reason):
        f = ctx.finding(rule, path, verdict, reason); f['source_checked_at'] = '2026-10-04'; results.append(f)
    if resource.type == 'AWS::APS::Scraper' and value(ctx, resource, '/properties/Source/EksConfiguration') is not ABSENT:
        emit('APS_SCRAPER_VPC_ALIGNMENT', '/properties/Source/EksConfiguration', scraper_vpc(ctx, resource), 'uniquely linked EKS and scraper subnet/security-group literal VPC IDs agree; unknown/conditional/external identity, endpoint access, routing and permissions remain open')
    return results
