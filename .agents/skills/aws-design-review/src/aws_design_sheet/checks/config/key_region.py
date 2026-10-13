"""Resolve destination bucket and KMS key Regions without assuming caller Region."""
import re
from ..common.context_values import linked, value
from ..common.field_reads import read
from ..common.literals import literal
from ..common.scoped_resolution import resolved


def bucket_region(ctx,r):
    bucket=linked(ctx,r,'/properties/S3BucketName','AWS::S3::Bucket')
    if resolved(bucket):return bucket.scope.region
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path=='/properties/S3BucketName']
    if len(refs)!=1 or refs[0].condition:return None
    bucket=ctx.by_id.get(refs[0].target_resource_id)
    name=read(ctx,r,'/properties/S3BucketName')
    if not resolved(bucket) or bucket.type!='AWS::S3::Bucket' or bucket.scope.environment!=r.scope.environment:return None
    if not literal(name) or not re.fullmatch('[a-z0-9.-]{3,63}',name) or value(ctx,bucket,'/properties/BucketName')!=name:return None
    ctx.evidence.extend(refs[0].evidence_ids)
    return bucket.scope.region


def config_key_region(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    region=bucket_region(ctx,r)
    raw=value(ctx,r,'/properties/S3KmsKeyArn')
    match=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:kms:([a-z0-9-]+):[0-9]{12}:key/[A-Za-z0-9-]+',raw) if literal(raw) else None
    key_region=match[1] if match else None
    if key_region is None:
        for kind in ('AWS::KMS::Key','AWS::KMS::ReplicaKey'):
            key=linked(ctx,r,'/properties/S3KmsKeyArn',kind)
            if resolved(key):key_region=key.scope.region
    if region is None or key_region is None:return 'NEEDS_REVIEW'
    return 'PASS' if region==key_region else 'FAIL'
