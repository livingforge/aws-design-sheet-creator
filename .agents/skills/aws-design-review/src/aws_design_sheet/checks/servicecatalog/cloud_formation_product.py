"""Checks for AWS::ServiceCatalog::CloudFormationProduct."""
from ..registry import resource_check
from ..common.catalog_values import catalog_value


@resource_check('AWS::ServiceCatalog::CloudFormationProduct')
def evaluate_servicecatalog_cloud_formation_product(design,resource):return catalog_value(design,resource)
