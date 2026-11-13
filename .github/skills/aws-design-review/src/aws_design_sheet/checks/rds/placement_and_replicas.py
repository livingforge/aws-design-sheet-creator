"""RDS placement and read-replica sources that AWS refuses although cfn-lint 1.57.2 accepts them.

Each was refused by AWS in aws-emulator-evaluation-suite:

- a DB proxy whose subnets lie in more than one VPC (InvalidParameterCombination);
- a DB instance in an Availability Zone its DB subnet group does not cover
  (InvalidVPCNetworkStateFault);
- a read replica of a source without automated backups ("Automated backups are not enabled for
  this database instance", InvalidDBInstanceState). CloudFormation's documented default
  BackupRetentionPeriod of 1 applies when the source omits it.
"""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.vpc_membership import vpc_membership

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
API = 'https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/'
SOURCES = {
    'RDS_DB_PROXY_VPC_MEMBERSHIP': [CF + 'aws-resource-rds-dbproxy.html', API + 'API_CreateDBProxy.html'],
    'RDS_INSTANCE_AZ_IN_SUBNET_GROUP': [CF + 'aws-resource-rds-dbinstance.html', API + 'API_CreateDBInstance.html'],
    'RDS_READ_REPLICA_SOURCE_BACKUPS': [CF + 'aws-resource-rds-dbinstance.html', API + 'API_CreateDBInstanceReadReplica.html'],
}


@resource_check('AWS::RDS::DBProxy')
def evaluate_db_proxy_vpc_membership(design, resource):
    return vpc_membership(_Context(design, resource), resource, '/properties', 'RDS_DB_PROXY_VPC_MEMBERSHIP',
                          subnet_key='VpcSubnetIds', security_group_key='VpcSecurityGroupIds',
                          finding_path='/properties/VpcSubnetIds')


def _subnet_group_zones(ctx, group):
    """Literal AvailabilityZone of every subnet of a linked DB subnet group, or None if any is unknown."""
    subnets = value(ctx, group, '/properties/SubnetIds')
    links = [r for r in ctx.design.relations if r.source_resource_id == group.id
             and r.source_path.startswith('/properties/SubnetIds/')]
    count = len(subnets) if isinstance(subnets, list) else len(links) if subnets is ABSENT else 0
    if not count:
        return None
    zones = set()
    for i in range(count):
        subnet = linked(ctx, group, f'/properties/SubnetIds/{i}', 'AWS::EC2::Subnet')
        zone = value(ctx, subnet, '/properties/AvailabilityZone') if subnet is not None else None
        if not literal(zone):
            return None
        zones.add(zone)
    return zones


def _availability_zone(design, resource):
    ctx = _Context(design, resource)
    zone = value(ctx, resource, '/properties/AvailabilityZone')
    if zone is ABSENT:
        return []
    group = linked(ctx, resource, '/properties/DBSubnetGroupName', 'AWS::RDS::DBSubnetGroup')
    if group is None:
        return []  # no subnet group in the design: the default VPC or an existing group
    zones = _subnet_group_zones(ctx, group) if literal(zone) else None
    if zones is None:
        verdict, reason = 'NEEDS_REVIEW', "the instance's or the subnet group's Availability Zones are unresolved"
    elif zone in zones:
        verdict, reason = 'PASS', 'the Availability Zone is covered by the DB subnet group'
    else:
        verdict, reason = 'FAIL', f'{zone} is not among the DB subnet group\'s zones ({", ".join(sorted(zones))})'
    return [ctx.finding('RDS_INSTANCE_AZ_IN_SUBNET_GROUP', '/properties/AvailabilityZone', verdict, reason)]


def _read_replica_source(design, resource):
    ctx = _Context(design, resource)
    source = linked(ctx, resource, '/properties/SourceDBInstanceIdentifier', 'AWS::RDS::DBInstance')
    if source is None:
        return []  # a literal identifier or ARN names an instance outside the design
    retention = value(ctx, source, '/properties/BackupRetentionPeriod')
    days = 1 if retention is ABSENT else retention if type(retention) is int else (
        int(retention) if isinstance(retention, str) and retention.isdigit() else None)
    if days is None:
        verdict, reason = 'NEEDS_REVIEW', "the source's BackupRetentionPeriod is unresolved"
    elif days == 0:
        verdict, reason = 'FAIL', 'the source DB instance has BackupRetentionPeriod 0, so automated backups are off'
    else:
        verdict, reason = 'PASS', 'the source DB instance keeps automated backups'
    return [ctx.finding('RDS_READ_REPLICA_SOURCE_BACKUPS', '/properties/SourceDBInstanceIdentifier', verdict, reason)]


@resource_check('AWS::RDS::DBInstance')
def evaluate_instance_placement_and_replica_source(design, resource):
    return _availability_zone(design, resource) + _read_replica_source(design, resource)
