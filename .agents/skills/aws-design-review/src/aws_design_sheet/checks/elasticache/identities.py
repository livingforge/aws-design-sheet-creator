"""Checks for these resource types:

- AWS::ElastiCache::CacheCluster
- AWS::ElastiCache::ReplicationGroup
- AWS::ElastiCache::UserGroup
"""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CACHECLUSTER_NOTIFICATION_ACCOUNT': [CF+'aws-resource-elasticache-cachecluster.html'],
    'REPLICATIONGROUP_NOTIFICATION_ACCOUNT': [CF+'aws-resource-elasticache-replicationgroup.html'],
    'REPLICATIONGROUP_ENGINE_VALUES': [CF+'aws-resource-elasticache-replicationgroup.html'],
    'ELASTICACHE_REDIS_DEFAULT_USER': [CF+'aws-resource-elasticache-usergroup.html',CF+'aws-resource-elasticache-user.html'],
}


@resource_check(
    'AWS::ElastiCache::CacheCluster',
    'AWS::ElastiCache::ReplicationGroup',
    'AWS::ElastiCache::UserGroup',
)
def evaluate_elasticache_identities(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type in ('AWS::ElastiCache::CacheCluster','AWS::ElastiCache::ReplicationGroup'):
        path = '/properties/NotificationTopicArn'
        raw = value(ctx,resource,path)
        if raw is not ABSENT:
            match = re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:sns:[a-z0-9-]+:([0-9]{12}):[A-Za-z0-9_-]+(?:\.fifo)?',raw) if literal(raw) else None
            verdict = 'NEEDS_REVIEW' if not match or not re.fullmatch(r'[0-9]{12}',resource.scope.account) else 'PASS' if match[1]==resource.scope.account else 'FAIL'
            rule = 'CACHECLUSTER_NOTIFICATION_ACCOUNT' if resource.type.endswith('CacheCluster') else 'REPLICATIONGROUP_NOTIFICATION_ACCOUNT'
            emit(rule,path,verdict,'account component of a recognized literal SNS topic ARN must match cluster owner; topic existence, permissions, FIFO and regional compatibility remain separate')
    if resource.type == 'AWS::ElastiCache::ReplicationGroup':
        path = '/properties/Engine'
        raw = value(ctx,resource,path)
        if raw is not ABSENT:
            verdict = 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in ('redis','valkey') else 'NEEDS_REVIEW' if raw.lower() in ('redis','valkey') else 'FAIL'
            emit('REPLICATIONGROUP_ENGINE_VALUES',path,verdict,'published lowercase redis/valkey values; case-only variants remain held because normalization is undocumented; defaults and engine-version compatibility remain separate')
    if resource.type == 'AWS::ElastiCache::UserGroup':
        path = '/properties/UserIds'
        raw = value(ctx,resource,path)
        engine = value(ctx,resource,'/properties/Engine')
        if raw is not ABSENT:
            verdict = 'NEEDS_REVIEW'
            if engine=='redis' and isinstance(raw,list) and len(raw)<=1000:
                names = []
                for i in range(len(raw)):
                    user = linked(ctx,resource,path+'/'+str(i),'AWS::ElastiCache::User')
                    names.append(value(ctx,user,'/properties/UserName') if user else None)
                verdict = 'PASS' if 'default' in names else 'FAIL' if all(literal(n) for n in names) else 'NEEDS_REVIEW'
            emit('ELASTICACHE_REDIS_DEFAULT_USER',path,verdict,'explicit redis groups require a linked user named default; IDs are not treated as usernames; Valkey, unknown identities and actual deployed membership remain held')
    return results
