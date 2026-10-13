"""Checks for AWS::EFS::FileSystem."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EFS_FILESYSTEM_MODES': [CF+'aws-resource-efs-filesystem.html'],
}


@resource_check('AWS::EFS::FileSystem')
def evaluate_efs_filesystem_modes(design, resource):
    ctx = _Context(design, resource)
    results = []
    def emit(rule, path, verdict, reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    enums = {
        'AWS::EFS::FileSystem': ('EFS_FILESYSTEM_MODES', [('PerformanceMode',('generalPurpose','maxIO')),('ThroughputMode',('bursting','provisioned','elastic'))]),
    }
    if resource.type in enums:
        rule, fields = enums[resource.type]
        for field, allowed in fields:
            path = '/properties/'+field
            raw = value(ctx,resource,path)
            if raw is not ABSENT:
                emit(rule,path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','explicit documented allowed values only; defaults, conditional applicability and related resource compatibility remain separate')
    return results
