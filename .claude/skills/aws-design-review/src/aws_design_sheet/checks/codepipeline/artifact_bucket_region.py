"""Checks for AWS::CodePipeline::Pipeline."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, read
from ..common.literals import expand, known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEPIPELINE_ARTIFACT_BUCKET_REGION': [CF+'aws-properties-codepipeline-pipeline-artifactstore.html',CF+'aws-properties-codepipeline-pipeline-artifactstoremap.html','https://docs.aws.amazon.com/codepipeline/latest/userguide/actions-create-cross-region.html'],
}


def artifact_region(ctx,resource,path,store_region=None):
    name = read(ctx,resource,path)
    refs = [r for r in ctx.design.relations if r.source_resource_id==resource.id and r.source_path==path]
    base=path.rsplit('/',1)[0]
    mapped=base.startswith('/properties/ArtifactStores/')
    if value(ctx,resource,base+'/Type')!='S3':return 'NEEDS_REVIEW'
    if mapped:
        if value(ctx,resource,'/properties/ArtifactStore') is not ABSENT:return 'NEEDS_REVIEW'
        expected=store_region
    else:
        if value(ctx,resource,'/properties/ArtifactStores') is not ABSENT:return 'NEEDS_REVIEW'
        expected=resource.scope.region
    if not known_scope(resource) or not literal(expected) or not re.fullmatch(r'[a-z]+(?:-[a-z]+)+-[0-9]+',expected):return 'NEEDS_REVIEW'
    if len(refs)!=1 or refs[0].condition:return 'NEEDS_REVIEW'
    if name is not ABSENT and (not literal(name) or not re.fullmatch(r'[a-zA-Z0-9.-]{3,63}',name)):return 'NEEDS_REVIEW'
    bucket=ctx.by_id.get(refs[0].target_resource_id)
    if bucket is None or bucket.type!='AWS::S3::Bucket' or not known_scope(bucket) or (bucket.scope.account,bucket.scope.environment)!=(resource.scope.account,resource.scope.environment):return 'NEEDS_REVIEW'
    if any(r.template is not None and r.template.state.value!='KNOWN' for r in (resource,bucket)):return 'NEEDS_REVIEW'
    if name is not ABSENT:
        actual=value(ctx,bucket,'/properties/BucketName')
        if not literal(actual) or actual!=name:return 'NEEDS_REVIEW'
    ctx.evidence.extend(refs[0].evidence_ids)
    ctx.dependencies.append(bucket.id+'/scope/region')
    return 'PASS' if bucket.scope.region==expected else 'FAIL'


@resource_check('AWS::CodePipeline::Pipeline')
def evaluate_codepipeline_artifact_bucket_region(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::CodePipeline::Pipeline':
        paths=[('/properties/ArtifactStore/Location',None)]
        for base in expand(ctx,resource,'/properties/ArtifactStores/*'):
            if re.fullmatch(r'/properties/ArtifactStores/\d+',base):
                paths.append((base+'/ArtifactStore/Location',value(ctx,resource,base+'/Region')))
            else:
                emit('CODEPIPELINE_ARTIFACT_BUCKET_REGION',base,'NEEDS_REVIEW','Unknown or malformed artifact-store collection; Region mapping is unresolved.')
        for path,region in paths:
            if value(ctx,resource,path) is not ABSENT:
                emit('CODEPIPELINE_ARTIFACT_BUCKET_REGION',path,artifact_region(ctx,resource,path,region),'S3 bucket Region must match the pipeline for ArtifactStore or the explicit mapped Region for ArtifactStores. Uses unique unconditional references with known same-account/environment scope and consistent explicit bucket names. Unknown/external identity and store exclusivity remain reviewable; permissions and live availability are separate.')
    return results
