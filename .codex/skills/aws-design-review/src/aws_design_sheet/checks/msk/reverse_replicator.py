"""Recognize explicitly declared reverse MSK replication directions."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'MSK_ENHANCED_REVERSE_REPLICATOR':[CF+'aws-resource-msk-replicator.html',CF+'aws-properties-msk-replicator-consumergroupreplication.html',CF+'aws-properties-msk-replicator-replicationinfo.html']}
BASE='/properties/ReplicationInfoList/0/'


def direction(ctx,r):
    if not resolved(r):return None
    rows=value(ctx,r,'/properties/ReplicationInfoList')
    if not isinstance(rows,list) or len(rows)!=1:return None
    names=[]
    for side in ('Source','Target'):
        if value(ctx,r,BASE+side+'KafkaClusterId') is not ABSENT:return None
        arn=value(ctx,r,BASE+side+'KafkaClusterArn')
        if not isinstance(arn,str) or not re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):kafka:[a-z0-9-]+:[0-9]{12}:cluster/[A-Za-z0-9_-]+/[A-Za-z0-9-]+',arn):return None
        names.append(arn)
    return tuple(names) if names[0]!=names[1] else None


@resource_check('AWS::MSK::Replicator')
def evaluate_msk_reverse_replicator(design,resource):
    if resource.type!='AWS::MSK::Replicator':return []
    ctx=_Context(design,resource)
    mode=value(ctx,resource,BASE+'ConsumerGroupReplication/ConsumerGroupOffsetSyncMode')
    verdict='NOT_APPLICABLE' if resolved(resource) and (mode is ABSENT or mode=='LEGACY') else 'NEEDS_REVIEW'
    if mode=='ENHANCED' and (own:=direction(ctx,resource)):
        for other in design.resources:
            if other.id==resource.id or other.type!=resource.type:continue
            if (other.scope.account,other.scope.environment)!=(resource.scope.account,resource.scope.environment):continue
            if direction(ctx,other)==own[::-1]:verdict='PASS';break
    f=ctx.finding('MSK_ENHANCED_REVERSE_REPLICATOR',BASE+'ConsumerGroupReplication/ConsumerGroupOffsetSyncMode',verdict,'ENHANCED requires a corresponding reverse replicator. PASS establishes only a declared reversed pair of literal MSK cluster ARNs in the same account/environment, allowing different replicator Regions. External replicators, dynamic references, Apache Kafka IDs, conflicting ID/ARN declarations and incomplete direction records remain reviewable. Missing inventory does not prove absence; topic-selector compatibility, deployment and live replication are separate.')
    f['source_checked_at']='2026-10-04';return [f]
