"""Checks for AWS::DMS::ReplicationSubnetGroup."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DMS_SUBNET_GROUP_ZONES': [CF+'aws-resource-dms-replicationsubnetgroup.html'],
}


@resource_check('AWS::DMS::ReplicationSubnetGroup')
def evaluate_dms_subnet_group_zones(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    if resource.type == 'AWS::DMS::ReplicationSubnetGroup':
        p = '/properties/SubnetIds'
        raw = get(p)
        if raw is not ABSENT:
            pending = not isinstance(raw, list) or not known_scope(resource)
            zones = set()
            if isinstance(raw, list):
                for i in range(len(raw)):
                    subnet = linked(ctx, resource, p+'/'+str(i), 'AWS::EC2::Subnet')
                    zone = value(ctx, subnet, '/properties/AvailabilityZone') if subnet else UNKNOWN
                    if literal(zone) and re.fullmatch(re.escape(resource.scope.region)+r'[a-z]', zone):
                        zones.add(zone)
                    else:
                        pending = True
            verdict = 'NEEDS_REVIEW' if pending else 'PASS' if len(zones) >= 2 else 'FAIL'
            emit('DMS_SUBNET_GROUP_ZONES', p, verdict, 'requires two explicit standard AZs from same-scope linked subnets; AZ IDs, Local Zones, unknown/external subnet identities and live network state remain held')
    return results
