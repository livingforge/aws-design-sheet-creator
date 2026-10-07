"""Checks for these resource types:

- AWS::FSx::DataRepositoryAssociation
- AWS::FSx::FileSystem
- AWS::FSx::StorageVirtualMachine
"""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'FSX_DRA_FILESYSTEM_SUPPORT': [CF+'aws-resource-fsx-datarepositoryassociation.html'],
    'FSX_AUDIT_DESTINATION_SCOPE': [CF+'aws-properties-fsx-filesystem-auditlogconfiguration.html'],
    'FSX_SVM_NETBIOS_LENGTH': [CF+'aws-properties-fsx-storagevirtualmachine-activedirectoryconfiguration.html'],
}


def dra_support(ctx,resource):
    fs = linked(ctx,resource,'/properties/FileSystemId','AWS::FSx::FileSystem')
    if fs is None:
        return 'NEEDS_REVIEW'
    kind = value(ctx,fs,'/properties/FileSystemType')
    if kind in ('WINDOWS','ONTAP','OPENZFS'):
        return 'FAIL'
    if kind!='LUSTRE':
        return 'NEEDS_REVIEW'
    version = value(ctx,fs,'/properties/FileSystemTypeVersion')
    deployment = value(ctx,fs,'/properties/LustreConfiguration/DeploymentType')
    match = re.fullmatch(r'([0-9]{1,3})\.([0-9]{1,3})(?:\.([0-9]{1,3}))?',version) if literal(version) else None
    if deployment=='SCRATCH_1' or match and (int(match[1]),int(match[2]))<(2,12):
        return 'FAIL'
    return 'PASS' if match and deployment in ('SCRATCH_2','PERSISTENT_1','PERSISTENT_2') else 'NEEDS_REVIEW'


@resource_check(
    'AWS::FSx::DataRepositoryAssociation',
    'AWS::FSx::FileSystem',
    'AWS::FSx::StorageVirtualMachine',
)
def evaluate_fsx_capabilities_and_links(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::FSx::DataRepositoryAssociation':
        emit('FSX_DRA_FILESYSTEM_SUPPORT','/properties/FileSystemId',dra_support(ctx,resource),'explicit linked filesystem must be Lustre 2.12+ and not SCRATCH_1; unknown versions/deployments, omitted defaults, actual release catalog and external filesystems remain held')
    if resource.type == 'AWS::FSx::FileSystem':
        path = '/properties/WindowsConfiguration/AuditLogConfiguration/AuditLogDestination'
        raw = value(ctx,resource,path)
        if raw is not ABSENT:
            match = re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:(logs|firehose):([a-z0-9-]+):([0-9]{12}):(.+)',raw) if literal(raw) else None
            supported = match is not None and ((match[1]=='logs' and match[4].startswith('log-group:')) or (match[1]=='firehose' and match[4].startswith('deliverystream/')))
            verdict = 'NEEDS_REVIEW' if not supported or not known_scope(resource) else 'PASS' if (match[2],match[3])==(resource.scope.region,resource.scope.account) else 'FAIL'
            emit('FSX_AUDIT_DESTINATION_SCOPE',path,verdict,'explicit recognized Logs/Firehose ARN account and Region must match filesystem; partition, required name prefixes, existence and permissions remain separate')
    if resource.type == 'AWS::FSx::StorageVirtualMachine':
        path = '/properties/ActiveDirectoryConfiguration/NetBiosName'
        raw = value(ctx,resource,path)
        if raw is not ABSENT:
            emit('FSX_SVM_NETBIOS_LENGTH',path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if len(raw)<=15 else 'FAIL','explicit NetBIOS name maximum 15 characters only; character grammar and domain membership remain separate')
    return results
