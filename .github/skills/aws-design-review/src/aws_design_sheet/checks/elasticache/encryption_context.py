"""ElastiCache encryption engine gates and explicit VPC placement."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved
from ..common.vpc_identity import vpc_identity

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={rule:[CF+'aws-resource-elasticache-replicationgroup.html',CF+'aws-resource-elasticache-subnetgroup.html','https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/at-rest-encryption.html','https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/in-transit-encryption.html'] for rule in ('CACHE_ENCRYPTION_ENGINE_VERSION','CACHE_ENCRYPTION_VPC_CONDITION')}


def engine_gate(engine,raw,at_rest):
    if engine not in ('redis','valkey') or not isinstance(raw,str):return 'NEEDS_REVIEW'
    m=re.fullmatch(r'([0-9]{1,3})\.([0-9]{1,3})(?:\.([0-9]{1,3}))?',raw)
    if not m:return 'NEEDS_REVIEW'
    a,b=map(int,m.groups()[:2]);patch=int(m[3]) if m[3] is not None else None
    if engine=='valkey':return 'PASS' if (a,b)>=(7,2) else 'FAIL'
    if at_rest:
        if (a,b)>(4,0) or ((a,b)==(4,0) and patch is not None and patch>=10):return 'PASS'
        if (a,b)==(4,0) or ((a,b)==(3,2) and patch in (None,6)):return 'NEEDS_REVIEW'
    else:
        if a>=4 or (a,b,patch)==(3,2,6):return 'PASS'
        if (a,b)==(3,2) and patch is None:return 'NEEDS_REVIEW'
    return 'FAIL'


def vpc(ctx,r):
    group=linked(ctx,r,'/properties/CacheSubnetGroupName','AWS::ElastiCache::SubnetGroup')
    if not resolved(group):return 'NEEDS_REVIEW'
    raw=read(ctx,r,'/properties/CacheSubnetGroupName')
    name=value(ctx,group,'/properties/CacheSubnetGroupName')
    if raw is not ABSENT and (not literal(raw) or not literal(name) or raw!=name.lower()):return 'NEEDS_REVIEW'
    ids=value(ctx,group,'/properties/SubnetIds')
    if not isinstance(ids,list) or not 0<len(ids)<=256:return 'NEEDS_REVIEW'
    identities=[]
    for i in range(len(ids)):
        subnet=linked(ctx,group,f'/properties/SubnetIds/{i}','AWS::EC2::Subnet')
        identity=vpc_identity(ctx,subnet)
        if identity is None:return 'NEEDS_REVIEW'
        identities.append(identity)
    return 'PASS' if len(set(identities))==1 else 'NEEDS_REVIEW'


@resource_check('AWS::ElastiCache::ReplicationGroup')
def evaluate_elasticache_encryption_context(design,resource):
    if resource.type!='AWS::ElastiCache::ReplicationGroup':return []
    ctx=_Context(design,resource);out=[]
    engine=value(ctx,resource,'/properties/Engine');version=value(ctx,resource,'/properties/EngineVersion')
    for prop in ('AtRestEncryptionEnabled','TransitEncryptionEnabled'):
        flag=value(ctx,resource,'/properties/'+prop)
        if flag is ABSENT and not (engine=='valkey' and prop=='AtRestEncryptionEnabled'):continue
        verdicts=('NEEDS_REVIEW','NEEDS_REVIEW')
        if resolved(resource):
            if flag is False:verdicts=('NOT_APPLICABLE','NOT_APPLICABLE')
            elif flag is True:verdicts=(engine_gate(engine,version,prop=='AtRestEncryptionEnabled'),vpc(ctx,resource))
        for rule,verdict in zip(SOURCES,verdicts):
            f=ctx.finding(rule,'/properties/'+prop,verdict,'Enabled encryption requires a supported explicit engine version and VPC placement. At-rest Redis 3.2.6/early 4.0 versions and omitted Valkey defaults differ between CFN and the developer guide, so these remain reviewable. Missing subnet inventory, external names, unknown patch levels and update-operation restrictions remain separate; PASS does not certify live encryption, node-family support or connectivity.')
            f['source_checked_at']='2026-10-04';out.append(f)
    return out
