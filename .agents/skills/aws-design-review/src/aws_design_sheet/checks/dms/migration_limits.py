"""Checks for AWS::DMS::EventSubscription, AWS::DMS::ReplicationConfig."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DMS_EVENT_SOURCE_TYPE': [CF+'aws-resource-dms-eventsubscription.html'],
    'DMS_CAPACITY_UNIT_VALUES': [CF+'aws-properties-dms-replicationconfig-computeconfig.html'],
}
DCUS = (1, 2, 4, 8, 16, 32, 64, 128, 192, 256, 384)


@resource_check('AWS::DMS::EventSubscription', 'AWS::DMS::ReplicationConfig')
def evaluate_dms_migration_limits(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    def enum(rule, p, allowed):
        raw = get(p)
        if raw is not ABSENT:
            emit(rule, p, 'NEEDS_REVIEW' if not (literal(raw) or (resource.type=='AWS::CodePipeline::CustomActionType' and raw=='')) else 'PASS' if raw in allowed else 'FAIL', 'documented explicit value only; applicability and service state remain separate')
    if resource.type == 'AWS::DMS::EventSubscription':
        enum('DMS_EVENT_SOURCE_TYPE','/properties/SourceType',('replication-instance','replication-task'))
    if resource.type == 'AWS::DMS::ReplicationConfig':
        for field in ('MinCapacityUnits','MaxCapacityUnits'):
            p = '/properties/ComputeConfig/'+field
            raw = get(p)
            if raw is not ABSENT:
                emit('DMS_CAPACITY_UNIT_VALUES',p,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if raw in DCUS else 'FAIL','explicit integer DCU value set only; min/max relation, regional availability and provisioning remain separate')
    return results
