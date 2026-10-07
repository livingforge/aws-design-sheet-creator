"""Region of the S3 bucket that holds a script."""
import re
from .context_values import value
from .field_reads import read
from .literals import known_scope, literal


def script_bucket_region(ctx,resource,path):
    name=read(ctx,resource,path)
    refs=[r for r in ctx.design.relations if r.source_resource_id==resource.id and r.source_path==path]
    if not known_scope(resource) or not literal(name) or not re.fullmatch(r'[a-z0-9.-]{3,63}',name) or len(refs)!=1 or refs[0].condition:
        return 'NEEDS_REVIEW'
    bucket=ctx.by_id.get(refs[0].target_resource_id)
    if bucket is None or bucket.type!='AWS::S3::Bucket' or not known_scope(bucket) or bucket.scope.environment!=resource.scope.environment:
        return 'NEEDS_REVIEW'
    if any(r.template is not None and r.template.state.value!='KNOWN' for r in (resource,bucket)):
        return 'NEEDS_REVIEW'
    actual=value(ctx,bucket,'/properties/BucketName')
    if not literal(actual) or actual!=name:
        return 'NEEDS_REVIEW'
    ctx.evidence.extend(refs[0].evidence_ids)
    return 'PASS' if bucket.scope.region==resource.scope.region else 'FAIL'
