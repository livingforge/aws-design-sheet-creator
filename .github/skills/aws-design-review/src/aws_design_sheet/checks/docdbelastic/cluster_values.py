"""Checks for AWS::DocDBElastic::Cluster."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DOCDBELASTIC_SHARD_BOUNDS': [CF+'aws-resource-docdbelastic-cluster.html'],
    'DOCDBELASTIC_AUTH_TYPE': [CF+'aws-resource-docdbelastic-cluster.html'],
}


@resource_check('AWS::DocDBElastic::Cluster')
def evaluate_docdbelastic_cluster_values(design, resource):
    ctx = _Context(design, resource)
    results = []
    def emit(rule, path, verdict, reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    enums = {
        'AWS::DocDBElastic::Cluster': ('DOCDBELASTIC_AUTH_TYPE', [('AuthType',('PLAIN_TEXT','SECRET_ARN'))]),
    }
    if resource.type in enums:
        rule, fields = enums[resource.type]
        for field, allowed in fields:
            path = '/properties/'+field
            raw = value(ctx,resource,path)
            if raw is not ABSENT:
                emit(rule,path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','explicit documented allowed values only; defaults, conditional applicability and related resource compatibility remain separate')
    if resource.type == 'AWS::DocDBElastic::Cluster':
        for field in ('ShardCapacity','ShardCount'):
            path = '/properties/'+field
            raw = value(ctx,resource,path)
            if raw is not ABSENT:
                verdict = 'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if (raw in (2,4,8,16,32,64) if field=='ShardCapacity' else raw<=32) else 'FAIL'
                emit('DOCDBELASTIC_SHARD_BOUNDS',path,verdict,'explicit shard capacity allowed values and shard count upper bound only; no unverified shard count minimum is imposed')
    return results
