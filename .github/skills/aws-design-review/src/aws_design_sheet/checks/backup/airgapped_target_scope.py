"""Checks for AWS::Backup::BackupPlan."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, known_scope, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'BACKUP_AIRGAPPED_TARGET_SCOPE': [CF+'aws-properties-backup-backupplan-backupruleresourcetype.html'],
}


@resource_check('AWS::Backup::BackupPlan')
def evaluate_backup_airgapped_target_scope(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(path): return value(ctx, resource, path)
    def emit(rule, path, verdict, reason):
        results.append(ctx.finding(rule, path, verdict, reason))
    def enum(rule, path, choices):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in choices else 'FAIL',
                 'explicit value compared with current documented allowed values; omitted and unresolved values are not inferred')
    def maximum(rule, path, limit):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not isinstance(raw, list) else 'PASS' if len(raw) <= limit else 'FAIL',
                 'explicit array length compared with documented maximum; member validity is separate')
    def required(rule, path, active):
        raw = get(path)
        verdict = 'NEEDS_REVIEW'
        if active:
            verdict = 'FAIL' if raw is ABSENT else 'PASS' if literal(raw) else 'NEEDS_REVIEW'
        emit(rule, path, verdict, 'checks presence only for an explicitly established triggering condition; credentials and resource existence remain external')

    if resource.type == 'AWS::Backup::BackupPlan':
        for path in expand(ctx,resource,'/properties/BackupPlan/BackupPlanRule/*/TargetLogicallyAirGappedBackupVaultArn'):
            raw = get(path)
            match = re.fullmatch(r'arn:(?:aws|aws-cn|aws-us-gov):backup:([a-z0-9-]+):([0-9]{12}):backup-vault:[A-Za-z0-9_-]+',raw) if literal(raw) else None
            verdict = 'NEEDS_REVIEW'
            if match and known_scope(resource):
                verdict = 'PASS' if (match[1],match[2]) == (resource.scope.region,resource.scope.account) else 'FAIL'
            emit('BACKUP_AIRGAPPED_TARGET_SCOPE',path,verdict,'checks explicit vault ARN account and region against known design scope; vault existence and supported resource types remain external')
    return results
