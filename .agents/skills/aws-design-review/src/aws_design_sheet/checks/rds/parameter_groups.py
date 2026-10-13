"""Checks for AWS::RDS::DBCluster, AWS::RDS::DBInstance."""
from __future__ import annotations

from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN

CFN = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'RDS_PARAMETER_GROUP_ENGINE': [CFN + 'aws-resource-rds-dbparametergroup.html',
                                    CFN + 'aws-resource-rds-dbclusterparametergroup.html'],
    'RDS_CLUSTER_PARAMETER_GROUP_FAMILY': [CFN + 'aws-resource-rds-dbcluster.html',
                                            CFN + 'aws-resource-rds-dbclusterparametergroup.html'],
}
PARAMETER_FAMILY_ENGINES = {
    'mysql8.0': 'mysql', 'postgres13': 'postgres',
    'aurora-mysql5.7': 'aurora-mysql', 'aurora-mysql8.0': 'aurora-mysql',
    'aurora-postgresql14': 'aurora-postgresql',
}


@resource_check('AWS::RDS::DBInstance', 'AWS::RDS::DBCluster')
def rds_parameter_groups(design, resource):
    cluster = resource.type == 'AWS::RDS::DBCluster'
    bindings = [('DBClusterParameterGroupName', 'AWS::RDS::DBClusterParameterGroup'),
                ('DBInstanceParameterGroupName', 'AWS::RDS::DBParameterGroup')] if cluster else [
                    ('DBParameterGroupName', 'AWS::RDS::DBParameterGroup')]
    results = []
    families = {}
    for key, expected_type in bindings:
        ctx = _Context(design, resource)
        path = '/properties/' + key
        if value(ctx, resource, path) is ABSENT:
            continue
        group = linked(ctx, resource, path, expected_type)
        family = value(ctx, group, '/properties/Family') if group else UNKNOWN
        engine = value(ctx, resource, '/properties/Engine')
        expected = PARAMETER_FAMILY_ENGINES.get(family) if isinstance(family, str) else None
        verdict = ('NEEDS_REVIEW' if expected is None or not isinstance(engine, str) or not engine else
                   'PASS' if engine == expected else 'FAIL')
        results.append(ctx.finding('RDS_PARAMETER_GROUP_ENGINE', path, verdict,
            'engine must match the documented parameter family; engine-version compatibility and regional availability are separate'))
        families[key] = (family, ctx)
    if cluster and 'DBInstanceParameterGroupName' in families:
        instance_family, ctx = families['DBInstanceParameterGroupName']
        cluster_family, cluster_ctx = families.get('DBClusterParameterGroupName', (UNKNOWN, None))
        if cluster_ctx:
            ctx.evidence.extend(cluster_ctx.evidence)
            ctx.dependencies.extend(cluster_ctx.dependencies)
        known = all(isinstance(family, str) and family for family in (instance_family, cluster_family))
        verdict = ('PASS' if instance_family == cluster_family else 'FAIL') if known else 'NEEDS_REVIEW'
        results.append(ctx.finding('RDS_CLUSTER_PARAMETER_GROUP_FAMILY',
            '/properties/DBInstanceParameterGroupName', verdict,
            'instance and cluster parameter groups must use the same family; upgrade-time applicability is separate'))
    return results
