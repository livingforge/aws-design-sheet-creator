"""KMS alias restriction for explicit cross-account pipeline actions."""
import re
from ..registry import resource_check
from .key_references import referenced_key_kind, referenced_role_account
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'PIPELINE_CROSS_ACCOUNT_KEY_ALIAS':[CF+'aws-properties-codepipeline-pipeline-encryptionkey.html',CF+'aws-properties-codepipeline-pipeline-actiondeclaration.html',CF+'aws-properties-codepipeline-pipeline-artifactstoremap.html',CF+'aws-resource-codepipeline-pipeline.html','https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id',CF+'aws-resource-iam-role.html',CF+'aws-resource-kms-key.html',CF+'aws-resource-kms-replicakey.html',CF+'aws-resource-kms-alias.html']}


def role_account(raw):
    m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+',raw) if literal(raw) and len(raw)<=2048 else None
    return m[1] if m else None


def cross_account(ctx,r,region):
    pending=False;found=False
    for path in expand(ctx,r,'/properties/Stages/*/Actions/*'):
        if path.count('/')!=5:pending=True;continue
        action=value(ctx,r,path)
        if not isinstance(action,dict) or '$state' in action:pending=True;continue
        ar=value(ctx,r,path+'/Region')
        if ar is ABSENT:ar=r.scope.region
        if not literal(ar):pending=True;continue
        if ar!=region:continue
        found=True
        role_path=path+'/RoleArn';raw=value(ctx,r,role_path)
        if raw is ABSENT:role_path='/properties/RoleArn';raw=value(ctx,r,role_path)
        account=role_account(raw) or referenced_role_account(ctx,r,role_path)
        if account is None:pending=True
        elif account!=r.scope.account:return True
    return None if pending or not found else False


def key_verdict(ctx,r,path,region):
    if not resolved(r) or not literal(region):return 'NEEDS_REVIEW'
    cross=cross_account(ctx,r,region)
    if cross is None:return 'NEEDS_REVIEW'
    if cross is False:return 'NOT_APPLICABLE'
    key_type=value(ctx,r,path.rsplit('/',1)[0]+'/Type')
    if key_type is not ABSENT and key_type!='KMS':return 'NEEDS_REVIEW'
    kind=referenced_key_kind(ctx,r,path)
    if kind:return 'FAIL' if kind=='alias' else 'PASS'
    raw=value(ctx,r,path)
    if not literal(raw) or len(raw)>2048:return 'NEEDS_REVIEW'
    if re.fullmatch(r'(?:arn:aws(?:-[a-z0-9-]+)?:kms:[a-z0-9-]+:[0-9]{12}:)?alias/[A-Za-z0-9/_-]+',raw):return 'FAIL'
    key=r'(?:[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|mrk-[0-9a-fA-F]{32})'
    if re.fullmatch(r'(?:arn:aws(?:-[a-z0-9-]+)?:kms:[a-z0-9-]+:[0-9]{12}:key/)?'+key,raw):return 'PASS'
    return 'NEEDS_REVIEW'


@resource_check('AWS::CodePipeline::Pipeline')
def evaluate_codepipeline_key_alias(design,resource):
    if resource.type!='AWS::CodePipeline::Pipeline':return []
    ctx=_Context(design,resource);results=[]
    paths=[('/properties/ArtifactStore/EncryptionKey/Id',resource.scope.region)]
    for base in expand(ctx,resource,'/properties/ArtifactStores/*'):
        if base.count('/')==3:paths.append((base+'/ArtifactStore/EncryptionKey/Id',value(ctx,resource,base+'/Region')))
        else:paths.append((base,None))
    for path,region in paths:
        if value(ctx,resource,path) is ABSENT:continue
        verdict=key_verdict(ctx,resource,path,region)
        f=ctx.finding('PIPELINE_CROSS_ACCOUNT_KEY_ALIAS',path,verdict,'For a known action role in another account and the artifact store Region, accept a literal KMS key ID/ARN or explicit Key/ReplicaKey reference and reject a literal or linked Alias. Unknown roles, references and Region mappings remain reviewable. Key ownership, policies, existence and artifact access are separate.')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
