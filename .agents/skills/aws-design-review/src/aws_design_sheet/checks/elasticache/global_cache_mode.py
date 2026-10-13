"""Global datastore failover from explicitly identified member replication groups."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import read
from ..common.scoped_resolution import resolved
from .cluster_mode import enabled

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'GLOBALREPLICATIONGROUP_INFERRED_FAILOVER':[CF+'aws-resource-elasticache-globalreplicationgroup.html',CF+'aws-properties-elasticache-globalreplicationgroup-globalreplicationgroupmember.html',CF+'aws-resource-elasticache-replicationgroup.html']}
SOURCES['GLOBALREPLICATIONGROUP_INFERRED_FAILOVER'].append(CF+'aws-properties-elasticache-replicationgroup-nodegroupconfiguration.html')


def member(ctx,r,path):
    name=read(ctx,r,path+'/ReplicationGroupId');region=value(ctx,r,path+'/ReplicationGroupRegion')
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path+'/ReplicationGroupId']
    if not isinstance(name,str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,39}',name) or len(refs)!=1 or refs[0].condition:return None
    group=ctx.by_id.get(refs[0].target_resource_id)
    if not resolved(group) or group.type!='AWS::ElastiCache::ReplicationGroup':return None
    if (group.scope.account,group.scope.environment)!=(r.scope.account,r.scope.environment) or group.scope.region!=region:return None
    if value(ctx,group,'/properties/ReplicationGroupId')!=name:return None
    ctx.evidence.extend(refs[0].evidence_ids)
    return group


@resource_check('AWS::ElastiCache::GlobalReplicationGroup')
def evaluate_elasticache_global_cache_mode(design,resource):
    if resource.type!='AWS::ElastiCache::GlobalReplicationGroup':return []
    ctx=_Context(design,resource);verdict='NEEDS_REVIEW';path='/properties/AutomaticFailoverEnabled'
    if resolved(resource):
        members=value(ctx,resource,'/properties/Members');modes=[]
        if isinstance(members,list) and len(members)<=1000:
            for i in range(len(members)):
                group=member(ctx,resource,'/properties/Members/'+str(i))
                modes.append(enabled(ctx,group) if group else None)
        count=value(ctx,resource,'/properties/GlobalNodeGroupCount')
        clustered=True in modes or type(count) is int and count>1
        if clustered and False not in modes:
            flag=value(ctx,resource,path)
            verdict='PASS' if flag is True else 'FAIL' if flag is False else 'NEEDS_REVIEW'
    f=ctx.finding('GLOBALREPLICATIONGROUP_INFERRED_FAILOVER',path,verdict,
        'Cluster mode established by explicit member configuration or multiple global node groups requires automatic failover. Cross-Region member links require matching literal replication group ID, member Region, account and environment. Missing defaults, contradictory member modes and external identity remain reviewable.')
    f['source_checked_at']='2026-10-04'
    return [f]
