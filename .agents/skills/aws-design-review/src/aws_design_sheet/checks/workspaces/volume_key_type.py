"""Checks for AWS::WorkSpaces::Workspace."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.kms_key_types import key_type

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'WORKSPACES_VOLUME_KEY_TYPE': [CF+'aws-resource-workspaces-workspace.html',CF+'aws-resource-kms-key.html',CF+'aws-resource-kms-replicakey.html',CF+'aws-resource-kms-alias.html'],
}


@resource_check('AWS::WorkSpaces::Workspace')
def evaluate_workspaces_volume_key_type(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::WorkSpaces::Workspace':
        path='/properties/VolumeEncryptionKey'
        if value(ctx,resource,path) is not ABSENT:
            active=any(value(ctx,resource,'/properties/'+key) is True for key in ('RootVolumeEncryptionEnabled','UserVolumeEncryptionEnabled'))
            emit('WORKSPACES_VOLUME_KEY_TYPE',path,key_type(ctx,resource,path,allow_alias=True) if active else 'NEEDS_REVIEW','explicit enabled encryption uses a linked symmetric encryption key; bounded Alias/ReplicaKey references and documented KMS defaults apply. HMAC/asymmetric keys fail. Unknown specs/usages, external identity, effective policy and encryption requiredness remain held')
    return results
