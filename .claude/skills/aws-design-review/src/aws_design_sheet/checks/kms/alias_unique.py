"""Checks for AWS::KMS::Alias."""
from __future__ import annotations

from ..registry import resource_check
from ..common.design_uniqueness import unique_in_design


SOURCES = {
    "KMS_ALIAS_DESIGN_NAME_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kms-alias.html"],
}


@resource_check('AWS::KMS::Alias')
def kms_alias_unique(design: Design, resource: Resource) -> dict:
    return unique_in_design(design, resource, '/properties/AliasName', 'KMS_ALIAS_DESIGN_NAME_UNIQUE')
