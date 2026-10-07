"""Checks for AWS::RDS::DBInstance, AWS::RDS::CustomDBEngineVersion."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.required_values import required_value, uncertain

SOURCES = {
    'RDS_CUSTOM_ENGINE_KMS_REQUIRED': ['https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateCustomDBEngineVersion.html'],
    'RDS_NEW_INSTANCE_MASTER_USERNAME': ['https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html'],
}


@resource_check('AWS::RDS::DBInstance')
def evaluate_rds_new_instance_master_username(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/MasterUsername'
    engine = value(ctx, resource, '/properties/Engine')
    sources = [value(ctx, resource, '/properties/' + key) for key in (
        'DBSnapshotIdentifier', 'SourceDBInstanceIdentifier', 'SourceDBClusterIdentifier',
        'SourceDbiResourceId', 'SourceDBInstanceAutomatedBackupsArn', 'DBClusterIdentifier')]
    supported = ('mysql', 'postgres', 'mariadb', 'oracle-ee', 'oracle-ee-cdb', 'oracle-se2',
                 'oracle-se2-cdb', 'sqlserver-ee', 'sqlserver-se', 'sqlserver-ex', 'sqlserver-web',
                 'db2-ae', 'db2-se')
    if any(isinstance(v, str) and v and not uncertain(v) for v in sources) or engine in ('aurora', 'aurora-mysql', 'aurora-postgresql'):
        return []
    if any(v is not ABSENT for v in sources) or engine not in supported:
        verdict = 'NEEDS_REVIEW'
    else:
        verdict = required_value(ctx, resource, path)
    return [ctx.finding('RDS_NEW_INSTANCE_MASTER_USERNAME', path, verdict,
                       'ordinary creation of a documented RDS DB instance engine requires MasterUsername; restores, replicas and cluster members are excluded')]


@resource_check('AWS::RDS::CustomDBEngineVersion')
def evaluate_rds_custom_engine_version(design, resource):
    ctx = _Context(design, resource)
    engine = value(ctx, resource, '/properties/Engine')
    engines = ('custom-oracle-ee', 'custom-oracle-ee-cdb', 'custom-oracle-se2', 'custom-oracle-se2-cdb',
               'custom-sqlserver-ee', 'custom-sqlserver-se', 'custom-sqlserver-web', 'custom-sqlserver-dev')
    path = '/properties/KMSKeyId'
    if engine in engines:
        verdict = required_value(ctx, resource, path)
    elif engine in ('sqlserver-ee', 'sqlserver-se', 'sqlserver-dev-ee'):
        verdict = 'NOT_APPLICABLE'
    else:
        verdict = 'NEEDS_REVIEW'
    return [ctx.finding('RDS_CUSTOM_ENGINE_KMS_REQUIRED', path, verdict,
                        'documented RDS Custom engines require a KMS key; symmetry, permissions and future engine families require review')]
