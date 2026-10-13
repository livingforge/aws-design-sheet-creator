"""Checks for AWS::Elasticsearch::Domain."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'ELASTICSEARCH_SUBNET_ZONE_COUNT': [CF+'aws-properties-elasticsearch-domain-vpcoptions.html',CF+'aws-properties-elasticsearch-domain-zoneawarenessconfig.html'],
}


@resource_check('AWS::Elasticsearch::Domain')
def evaluate_elasticsearch_subnet_zone_count(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::Elasticsearch::Domain':
        path = '/properties/VPCOptions/SubnetIds'
        subnets = value(ctx,resource,path)
        if subnets is not ABSENT:
            enabled = value(ctx,resource,'/properties/ElasticsearchClusterConfig/ZoneAwarenessEnabled')
            count = value(ctx,resource,'/properties/ElasticsearchClusterConfig/ZoneAwarenessConfig/AvailabilityZoneCount')
            known = enabled is True and type(count) is int and count in (2,3) and isinstance(subnets,list)
            emit('ELASTICSEARCH_SUBNET_ZONE_COUNT',path,'NEEDS_REVIEW' if not known else 'PASS' if len(subnets)==count else 'FAIL','explicit enabled zone-awareness count must match explicit subnet array length; defaults, actual subnet AZ uniqueness/VPC membership and external domains remain held')
    return results
