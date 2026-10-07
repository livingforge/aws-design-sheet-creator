"""Compare independently stated cluster mode with parameter-group settings."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved
from .cluster_mode import parameter_mode

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'REPLICATIONGROUP_PARAMETER_MODE_MATCH':[CF+'aws-resource-elasticache-replicationgroup.html',CF+'aws-resource-elasticache-parametergroup.html','https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/modify-cluster-mode.html']}


@resource_check('AWS::ElastiCache::ReplicationGroup')
def evaluate_elasticache_parameter_mode(design,resource):
    if resource.type!='AWS::ElastiCache::ReplicationGroup':return []
    ctx=_Context(design,resource);path='/properties/CacheParameterGroupName'
    raw=value(ctx,resource,path);verdict='NEEDS_REVIEW'
    if raw is ABSENT:return []
    if resolved(resource):
        actual=parameter_mode(ctx,resource)
        if actual is None and not any(ref.source_resource_id==resource.id and ref.source_path==path for ref in design.relations):
            if raw=='default.redis3.2.cluster.on':actual=True
            elif raw=='default.redis3.2':actual=False
        mode=value(ctx,resource,'/properties/ClusterMode')
        expected=True if mode=='enabled' else False if mode=='disabled' else None
        count=value(ctx,resource,'/properties/NumNodeGroups')
        if mode is ABSENT and type(count) is int and count>1:expected=True
        if actual is not None and expected is not None:verdict='PASS' if actual==expected else 'FAIL'
    return [ctx.finding('REPLICATIONGROUP_PARAMETER_MODE_MATCH',path,verdict,
        'An explicitly enabled or disabled cluster mode must match the parameter group cluster-enabled setting. More than one shard independently establishes enabled mode when ClusterMode is omitted. Only two documented default names are recognized. Compatible migration, unknown values and external/custom names require review; engine-family compatibility is a separate condition.')]
