"""Checks for AWS::ObservabilityAdmin::OrganizationCentralizationRule."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'OBSERVABILITY_LOG_KEY_SCOPE': [CF+'aws-properties-observabilityadmin-organizationcentralizationrule-logsencryptionconfiguration.html',CF+'aws-properties-observabilityadmin-organizationcentralizationrule-logsbackupconfiguration.html'],
}
DEST='/properties/Rule/Destination'
LOGS=DEST+'/DestinationLogsConfiguration'


def key_scope(ctx,resource,backup):
    if not resolved(resource):return 'NEEDS_REVIEW'
    base=LOGS+('/BackupConfiguration' if backup else '/LogsEncryptionConfiguration')
    if not backup and value(ctx,resource,base+'/EncryptionStrategy')!='CUSTOMER_MANAGED':return 'NEEDS_REVIEW'
    raw=value(ctx,resource,base+'/KmsKeyArn')
    account=value(ctx,resource,DEST+'/Account')
    region=value(ctx,resource,(base if backup else DEST)+'/Region')
    if not all(literal(v) for v in (raw,account,region)) or not re.fullmatch(r'[0-9]{12}',account) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]+',region):return 'NEEDS_REVIEW'
    match=re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):kms:([a-z]{2}(?:-[a-z]+)+-[0-9]+):([0-9]{12}):key/[A-Za-z0-9-]+',raw)
    if not match:return 'NEEDS_REVIEW'
    return 'PASS' if (match[2],match[3])==(region,account) else 'FAIL'


@resource_check('AWS::ObservabilityAdmin::OrganizationCentralizationRule')
def evaluate_observabilityadmin_log_key_scope(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::ObservabilityAdmin::OrganizationCentralizationRule':
        for backup in (False,True):
            path=LOGS+('/BackupConfiguration' if backup else '/LogsEncryptionConfiguration')+'/KmsKeyArn'
            if value(ctx,resource,path) is not ABSENT:
                emit('OBSERVABILITY_LOG_KEY_SCOPE',path,key_scope(ctx,resource,backup),'literal KMS key ARN must match explicit primary destination account and primary/backup Region; unknown/default destination, partition, aliases, organization membership, key existence and permissions remain held')
    return results
