"""Checks for AWS::ElastiCache::CacheCluster, AWS::ElastiCache::ReplicationGroup."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand
from ..common.map_cardinality import cardinality

SOURCES = {
    'ELASTICACHE_NODE_AZ_COUNT': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticache-cachecluster.html',
    ],
    'ELASTICACHE_CLUSTER_AZ_COUNT': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticache-replicationgroup.html',
    ],
    'ELASTICACHE_REPLICA_AZ_COUNT': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-elasticache-replicationgroup-nodegroupconfiguration.html',
    ],
}


@resource_check('AWS::ElastiCache::CacheCluster','AWS::ElastiCache::ReplicationGroup')
def evaluate_elasticache_az_counts(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 specs={'AWS::ElastiCache::CacheCluster':('ELASTICACHE_NODE_AZ_COUNT','PreferredAvailabilityZones','NumCacheNodes'),'AWS::ElastiCache::ReplicationGroup':('ELASTICACHE_CLUSTER_AZ_COUNT','PreferredCacheClusterAZs','NumCacheClusters')}
 if resource.type in specs:
  rule,key,count=specs[resource.type];p='/properties/'+key
  if get(p) is not ABSENT:emit(rule,p,cardinality(get(p),get('/properties/'+count)),'explicit AZ array length must match explicit integer node/cluster count; omitted counts and engine applicability remain separate')
 if resource.type=='AWS::ElastiCache::ReplicationGroup':
  for p in expand(ctx,resource,'/properties/NodeGroupConfiguration/*/ReplicaAvailabilityZones'):
   count=get(p.rsplit('/',1)[0]+'/ReplicaCount')
   if count is ABSENT:count=get('/properties/ReplicasPerNodeGroup')
   emit('ELASTICACHE_REPLICA_AZ_COUNT',p,cardinality(get(p),count),'replica AZ count uses explicit ReplicaCount, falling back to explicit ReplicasPerNodeGroup only when absent; unknown overrides held')
 return results
