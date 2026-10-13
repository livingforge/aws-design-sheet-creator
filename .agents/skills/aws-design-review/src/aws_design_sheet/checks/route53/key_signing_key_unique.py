"""Checks for AWS::Route53::KeySigningKey."""
from __future__ import annotations

from ..registry import resource_check
from ..common.design_uniqueness import unique_in_design


SOURCES = {
    "ROUTE53_KEY_SIGNING_NAME_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-keysigningkey.html"],
    "ROUTE53_KEY_SIGNING_KMS_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-keysigningkey.html"],
}


@resource_check('AWS::Route53::KeySigningKey')
def key_signing_key_unique(design: Design, resource: Resource) -> list[dict]:
    return [unique_in_design(design, resource, '/properties/Name', 'ROUTE53_KEY_SIGNING_NAME_UNIQUE', '/properties/HostedZoneId'),
            unique_in_design(design, resource, '/properties/KeyManagementServiceArn', 'ROUTE53_KEY_SIGNING_KMS_UNIQUE',
                             '/properties/HostedZoneId')]
