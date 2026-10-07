"""KMS key classification from explicit key resources: symmetric, HMAC and signing keys."""
import re
from .context_values import linked, value
from .field_reads import ABSENT, read
from .key_types_and_base64 import ASYMMETRIC
from .literals import literal
from .scoped_resolution import resolved

HMAC=('HMAC_224','HMAC_256','HMAC_384','HMAC_512')
SIGNING_ONLY=('ML_DSA_44','ML_DSA_65','ML_DSA_87','ECC_NIST_EDWARDS25519')


def partition(region):
    if region.startswith('cn-'):return 'aws-cn'
    if region.startswith('us-gov-'):return 'aws-us-gov'
    if '-iso' in region:return None
    return 'aws'


def primary_key(ctx,replica):
    path='/properties/PrimaryKeyArn';raw=read(ctx,replica,path)
    match=re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):kms:([a-z0-9-]+):([0-9]{12}):key/mrk-[a-f0-9]{32}',raw) if literal(raw) else None
    refs=[r for r in ctx.design.relations if r.source_resource_id==replica.id and r.source_path==path]
    if match is None or len(refs)!=1 or refs[0].condition:return None
    key=ctx.by_id.get(refs[0].target_resource_id)
    if not resolved(key) or key.type!='AWS::KMS::Key':return None
    if (key.scope.account,key.scope.environment)!=(replica.scope.account,replica.scope.environment):return None
    if key.scope.region==replica.scope.region or (match[2],match[3])!=(key.scope.region,key.scope.account):return None
    if match[1]!=partition(replica.scope.region) or match[1]!=partition(key.scope.region):return None
    if value(ctx,key,'/properties/MultiRegion') is not True:return None
    ctx.evidence.extend(refs[0].evidence_ids)
    return key


def key_type(ctx,resource,path,allow_alias=False):
    if not resolved(resource):return 'NEEDS_REVIEW'
    owner=resource;seen=set();key=None
    for _ in range(4):
        candidates=[linked(ctx,owner,path,kind) for kind in ('AWS::KMS::Key','AWS::KMS::ReplicaKey')+ (('AWS::KMS::Alias',) if allow_alias and owner is resource else ())]
        known=[r for r in candidates if resolved(r)]
        if len(known)!=1:return 'NEEDS_REVIEW'
        key=known[0]
        if key.id in seen:return 'NEEDS_REVIEW'
        seen.add(key.id)
        if key.type=='AWS::KMS::Alias':owner=key;path='/properties/TargetKeyId';continue
        if key.type=='AWS::KMS::ReplicaKey':key=primary_key(ctx,key)
        break
    if not resolved(key) or key.type!='AWS::KMS::Key':return 'NEEDS_REVIEW'
    spec=value(ctx,key,'/properties/KeySpec');usage=value(ctx,key,'/properties/KeyUsage')
    if spec is ABSENT:spec='SYMMETRIC_DEFAULT'
    if usage is ABSENT:usage='ENCRYPT_DECRYPT'
    if spec in ASYMMETRIC+HMAC+SIGNING_ONLY or usage in ('SIGN_VERIFY','GENERATE_VERIFY_MAC','KEY_AGREEMENT'):return 'FAIL'
    if spec=='SYMMETRIC_DEFAULT' and usage=='ENCRYPT_DECRYPT':return 'PASS'
    return 'NEEDS_REVIEW'
