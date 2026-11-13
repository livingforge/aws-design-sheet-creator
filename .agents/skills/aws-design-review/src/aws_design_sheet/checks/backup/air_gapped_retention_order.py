"""Retention window of a logically air-gapped backup vault.

AWS Backup refuses a MinRetentionDays above MaxRetentionDays (InvalidParameterValueException);
cfn-lint 1.57.2 does not compare the two. AWS refused it in aws-emulator-evaluation-suite.
"""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'BACKUP_AIR_GAPPED_RETENTION_ORDER': [CF + 'aws-resource-backup-logicallyairgappedbackupvault.html'],
}


def _days(raw):
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    return int(raw) if isinstance(raw, str) and raw.isdigit() else None


@resource_check('AWS::Backup::LogicallyAirGappedBackupVault')
def evaluate_air_gapped_retention_order(design, resource):
    ctx = _Context(design, resource)
    low = value(ctx, resource, '/properties/MinRetentionDays')
    high = value(ctx, resource, '/properties/MaxRetentionDays')
    if low is ABSENT or high is ABSENT:
        return []
    low, high = _days(low), _days(high)
    verdict = 'NEEDS_REVIEW' if low is None or high is None else 'PASS' if low <= high else 'FAIL'
    return [ctx.finding('BACKUP_AIR_GAPPED_RETENTION_ORDER', '/properties/MinRetentionDays', verdict,
                        'MinRetentionDays does not exceed MaxRetentionDays')]
