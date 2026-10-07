"""Cluster-mode constraints inferred from explicit parameter groups and shards."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'CACHECLUSTER_PARAMETER_CLUSTER_MODE':[CF+'aws-resource-elasticache-cachecluster.html',CF+'aws-resource-elasticache-parametergroup.html'],
 'REPLICATIONGROUP_INFERRED_FAILOVER':[CF+'aws-resource-elasticache-replicationgroup.html',CF+'aws-resource-elasticache-parametergroup.html'],
 'REPLICATIONGROUP_INFERRED_SNAPSHOT':[CF+'aws-resource-elasticache-replicationgroup.html',CF+'aws-resource-elasticache-parametergroup.html'],
}
for rule in ('REPLICATIONGROUP_INFERRED_FAILOVER','REPLICATIONGROUP_INFERRED_SNAPSHOT'):
    SOURCES[rule].append(CF+'aws-properties-elasticache-replicationgroup-nodegroupconfiguration.html')
SOURCES['REPLICATIONGROUP_INFERRED_FAILOVER'].append('https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/modify-cluster-mode.html')


def parameter_mode(ctx,r):
    group=linked(ctx,r,'/properties/CacheParameterGroupName','AWS::ElastiCache::ParameterGroup')
    if not resolved(r) or not resolved(group):return None
    raw=value(ctx,group,'/properties/Properties/cluster-enabled')
    return True if raw=='yes' else False if raw=='no' else None


def enabled(ctx,r):
    if not resolved(r):return None
    explicit=value(ctx,r,'/properties/ClusterMode')
    parameter=parameter_mode(ctx,r)
    if parameter is None and not any(ref.source_resource_id==r.id and ref.source_path=='/properties/CacheParameterGroupName' for ref in ctx.design.relations):
        name=value(ctx,r,'/properties/CacheParameterGroupName')
        if name=='default.redis3.2.cluster.on':parameter=True
        elif name=='default.redis3.2':parameter=False
    count=value(ctx,r,'/properties/NumNodeGroups')
    configurations=value(ctx,r,'/properties/NodeGroupConfiguration')
    ids=set()
    if isinstance(configurations,list) and len(configurations)<=1000:
        for i in range(len(configurations)):
            raw=value(ctx,r,'/properties/NodeGroupConfiguration/'+str(i)+'/NodeGroupId')
            if isinstance(raw,str) and re.fullmatch(r'[0-9]{1,4}',raw):ids.add(int(raw))
    configured=len(ids)>1
    if configured and type(count) is int and count==1:return None
    inferred=parameter is True or type(count) is int and count>1 or configured
    if parameter is False and (inferred or explicit=='enabled'):return None
    if explicit=='enabled':return True
    if explicit=='disabled':
        return None if inferred else False
    if explicit is not ABSENT:return None
    return True if inferred else False if parameter is False else None


@resource_check('AWS::ElastiCache::CacheCluster', 'AWS::ElastiCache::ReplicationGroup')
def evaluate_elasticache_cluster_mode(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::ElastiCache::CacheCluster':
        path='/properties/CacheParameterGroupName'
        if value(ctx,resource,path) is ABSENT:return []
        mode=parameter_mode(ctx,resource)
        emit('CACHECLUSTER_PARAMETER_CLUSTER_MODE',path,'FAIL' if mode is True else 'PASS' if mode is False else 'NEEDS_REVIEW',
             'A linked parameter group with cluster-enabled=yes cannot be used for CacheCluster creation. Only explicit yes/no values determine this condition; defaults, unknown or external groups remain reviewable.')
    if resource.type=='AWS::ElastiCache::ReplicationGroup':
        mode=enabled(ctx,resource)
        failover=value(ctx,resource,'/properties/AutomaticFailoverEnabled')
        if failover is ABSENT:failover=False
        requires_failover=mode
        if resolved(resource) and value(ctx,resource,'/properties/ClusterMode')=='compatible':requires_failover=True
        verdict='NOT_APPLICABLE' if requires_failover is False else 'NEEDS_REVIEW' if requires_failover is None else 'PASS' if failover is True else 'FAIL' if failover is False else 'NEEDS_REVIEW'
        emit('REPLICATIONGROUP_INFERRED_FAILOVER','/properties/AutomaticFailoverEnabled',verdict,
             'Cluster mode enabled and migration through compatible mode require automatic failover, whose documented default is false. Explicit linked parameters, two named documented default groups or multiple node groups can establish mode when ClusterMode is omitted; unresolved mode remains reviewable. Snapshot applicability in compatible mode is not inferred.')
        path='/properties/SnapshottingClusterId';raw=value(ctx,resource,path)
        if raw is not ABSENT:
            verdict='NOT_APPLICABLE' if mode is False else 'FAIL' if mode is True and literal(raw) else 'NEEDS_REVIEW'
            emit('REPLICATIONGROUP_INFERRED_SNAPSHOT',path,verdict,
                 'SnapshottingClusterId is unsupported with cluster mode enabled, including mode established by a parameter group or multiple shards. Unknown or contradictory inputs remain reviewable.')
    return results
