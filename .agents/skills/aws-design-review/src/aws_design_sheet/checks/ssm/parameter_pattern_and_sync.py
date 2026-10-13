"""Checks for AWS::SSM::Parameter, AWS::SSM::ResourceDataSync."""
from __future__ import annotations

import regex
from ..registry import resource_check
from ..common.design_uniqueness import _Context
from ..common.field_reads import ABSENT, read


SOURCES = {
    "SSM_PARAMETER_ALLOWED_PATTERN": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ssm-parameter.html#cfn-ssm-parameter-allowedpattern"],
    "SSM_RESOURCE_DATA_SYNC_KMS_REGION": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ssm-resourcedatasync.html"],
}


@resource_check('AWS::SSM::Parameter')
def ssm_parameter_pattern(design, resource):
    ctx = _Context(design, resource)
    pattern = read(ctx, resource, '/properties/AllowedPattern')
    if pattern is ABSENT:
        return []
    value = read(ctx, resource, '/properties/Value')
    kind = read(ctx, resource, '/properties/Type')
    verdict, reason = 'NEEDS_REVIEW', 'parameter pattern, type or value is unresolved'
    if isinstance(pattern, str) and isinstance(value, str) and kind == 'String':
        try:
            match = regex.fullmatch(pattern, value, timeout=0.05)
            verdict, reason = ('PASS', 'parameter value matches AllowedPattern') if match else (
                'FAIL', 'parameter value does not match AllowedPattern')
        except (regex.error, TimeoutError):
            reason = 'pattern syntax is unsupported or matching exceeded its time limit'
    return [ctx.finding('SSM_PARAMETER_ALLOWED_PATTERN', '/properties/Value', verdict, reason)]


@resource_check('AWS::SSM::ResourceDataSync')
def ssm_bucket_key_region(design, resource):
    ctx = _Context(design, resource)
    results = []
    for key_path, region_path in (('/properties/KMSKeyArn', '/properties/BucketRegion'),
                                  ('/properties/S3Destination/KMSKeyArn', '/properties/S3Destination/BucketRegion')):
        key = read(ctx, resource, key_path)
        if key is ABSENT:
            continue
        region = read(ctx, resource, region_path)
        match = regex.fullmatch(r'arn:[^:]+:kms:([^:]+):[0-9]{12}:key/.+', key) if isinstance(key, str) else None
        verdict = ('NEEDS_REVIEW' if not match or not isinstance(region, str) else
                   'PASS' if match[1] == region else 'FAIL')
        results.append(ctx.finding('SSM_RESOURCE_DATA_SYNC_KMS_REGION', key_path, verdict,
                                  'KMS key ARN Region must equal the destination bucket Region'))
    return results
