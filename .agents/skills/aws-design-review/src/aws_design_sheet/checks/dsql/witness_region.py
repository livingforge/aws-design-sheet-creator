"""Checks for AWS::DSQL::Cluster."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DSQL_WITNESS_REGION': [CF+'aws-resource-dsql-cluster.html'],
}


@resource_check('AWS::DSQL::Cluster')
def evaluate_dsql_witness_region(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    if resource.type == 'AWS::DSQL::Cluster':
        p = '/properties/MultiRegionProperties/WitnessRegion'
        region = get(p)
        if region is not ABSENT:
            known = literal(region) and re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d+', region) and known_scope(resource)
            emit('DSQL_WITNESS_REGION', p, 'NEEDS_REVIEW' if not known else 'FAIL' if region == resource.scope.region else 'PASS', 'witness and cluster deployment Regions must differ; regional catalog and multi-region peer configuration remain separate')
    return results
