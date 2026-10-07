"""Checks for AWS::Redshift::Cluster."""
from ..registry import resource_check
from ..common.map_cardinality import maintenance_duration


@resource_check('AWS::Redshift::Cluster')
def evaluate_redshift_cluster(design,resource):return maintenance_duration(design,resource)
