"""Checks for AWS::Cassandra::Keyspace, AWS::Cassandra::Table."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'KEYSPACE_DEPLOYMENT_REGION': [CF+'aws-properties-cassandra-keyspace-replicationspecification.html'],
    'CASSANDRA_REPLICA_APPLICABILITY': [CF+'aws-resource-cassandra-table.html'],
    'CASSANDRA_STATIC_CLUSTERING': [CF+'aws-properties-cassandra-table-column.html'],
}


@resource_check('AWS::Cassandra::Keyspace', 'AWS::Cassandra::Table')
def evaluate_cassandra_certificates(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):
        result=ctx.finding(rule,p,v,reason);result['source_checked_at']='2026-10-04';results.append(result)
    def enum(rule,p,allowed):
        raw=get(p)
        if raw is not ABSENT:emit(rule,p,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','literal value checked against current explicit CF allowed values; no omitted values inferred')
    if resource.type=='AWS::Cassandra::Keyspace':
        p='/properties/ReplicationSpecification/RegionList';raw=get(p);region=resource.scope.region;v='NEEDS_REVIEW'
        if raw is not ABSENT:
            if isinstance(raw,list) and re.fullmatch(r'[a-z]+(?:-[a-z]+)+-[0-9]+',region):
                values=[get(p+'/'+str(i)) for i in range(len(raw))]
                if region in values:v='PASS'
                elif all(literal(x) for x in values):v='FAIL'
            emit('KEYSPACE_DEPLOYMENT_REGION',p,v,'explicit RegionList includes the known deployment Region; actual regional enablement and update conditions remain external')
    if resource.type=='AWS::Cassandra::Table':
        p='/properties/ReplicaSpecifications'
        if get(p) is not ABSENT:
            keyspace=linked(ctx,resource,'/properties/KeyspaceName','AWS::Cassandra::Keyspace')
            strategy=value(ctx,keyspace,'/properties/ReplicationSpecification/ReplicationStrategy') if keyspace else None
            emit('CASSANDRA_REPLICA_APPLICABILITY',p,'PASS' if strategy=='MULTI_REGION' else 'NEEDS_REVIEW','replica-specific settings confirmed applicable for an explicitly linked MULTI_REGION keyspace; no rejection inferred for single-region or unknown strategy')
        for p in expand(ctx,resource,'/properties/RegularColumns/*/ColumnType'):
            raw=get(p);v='NEEDS_REVIEW'
            # Do not mistake a quoted UDT name, comment or nested type for STATIC.
            if literal(raw) and re.fullmatch(r'(?:ascii|bigint|blob|boolean|counter|date|decimal|double|duration|float|inet|int|smallint|text|time|timestamp|timeuuid|tinyint|uuid|varchar|varint)\s+STATIC',raw,re.I):
                clustering=get('/properties/ClusteringKeyColumns')
                if clustering is ABSENT or isinstance(clustering,list) and not clustering:v='FAIL'
                elif isinstance(clustering,list):v='PASS'
            else:
                if literal(raw) and re.fullmatch('[A-Za-z][A-Za-z0-9_]*',raw) and raw.upper()!='STATIC':continue
            emit('CASSANDRA_STATIC_CLUSTERING',p,v,'recognized primitive STATIC column requires at least one clustering column; complex/quoted type syntax and unknown collections held')
    return results
