"""The RDS administrator account name on PostgreSQL.

RDS keeps the user 'rdsadmin' for itself, and CreateDBInstance refuses it as the master user name
of a PostgreSQL instance (InvalidParameterValue); cfn-lint 1.57.2 does not report it. Only
PostgreSQL, where AWS refused it in aws-emulator-evaluation-suite, is checked.
"""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'RDS_POSTGRES_MASTER_USERNAME_RDSADMIN': [
        CF + 'aws-resource-rds-dbinstance.html',
        'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Appendix.PostgreSQL.CommonDBATasks.Roles.html'],
}


@resource_check('AWS::RDS::DBInstance')
def evaluate_postgres_master_username(design, resource):
    ctx = _Context(design, resource)
    if value(ctx, resource, '/properties/Engine') != 'postgres':
        return []
    name = value(ctx, resource, '/properties/MasterUsername')
    if not literal(name):
        return []
    verdict = 'FAIL' if name.lower() == 'rdsadmin' else 'PASS'
    return [ctx.finding('RDS_POSTGRES_MASTER_USERNAME_RDSADMIN', '/properties/MasterUsername', verdict,
                        "the master user name is not 'rdsadmin', the account RDS keeps for itself")]
