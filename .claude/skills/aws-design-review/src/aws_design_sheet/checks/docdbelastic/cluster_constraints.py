"""Checks for AWS::DocDBElastic::Cluster."""
from ..registry import resource_check
from ..common.map_cardinality import maintenance_duration


@resource_check('AWS::DocDBElastic::Cluster')
def evaluate_docdbelastic_cluster_constraints(design,resource):return maintenance_duration(design,resource)
