"""Checks for AWS::CloudFront::Distribution."""
from __future__ import annotations

from ..registry import resource_check
from ..common.design_uniqueness import _Context
from ..common.field_reads import ABSENT, UNKNOWN, read


SOURCES = {
    "CLOUDFRONT_ORIGIN_IDS_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudfront-distribution-origin.html"],
    "CLOUDFRONT_CACHE_TARGET_ORIGIN": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudfront-distribution-cachebehavior.html"],
    "CLOUDFRONT_GRPC_HTTP2_POST": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudfront-distribution-grpcconfig.html"],
}


@resource_check('AWS::CloudFront::Distribution')
def cloudfront_origins(design, resource):
    ctx = _Context(design, resource)
    base = '/properties/DistributionConfig'
    origins = read(ctx, resource, base + '/Origins')
    if origins is ABSENT:
        return []
    ids = []
    pending = not isinstance(origins, list)
    for i in range(len(origins) if isinstance(origins, list) else 0):
        value = read(ctx, resource, base + f'/Origins/{i}/Id')
        if isinstance(value, str):
            ids.append(value)
        else:
            pending = True
    unique = 'FAIL' if len(ids) != len(set(ids)) else 'NEEDS_REVIEW' if pending else 'PASS'
    results = [ctx.finding('CLOUDFRONT_ORIGIN_IDS_UNIQUE', base + '/Origins', unique,
                           'origin IDs must be unique within the distribution')]
    groups = read(ctx, resource, base + '/OriginGroups/Items')
    if isinstance(groups, list):
        for i in range(len(groups)):
            value = read(ctx, resource, base + f'/OriginGroups/Items/{i}/Id')
            if isinstance(value, str):
                ids.append(value)
            else:
                pending = True
    elif groups is not ABSENT:
        pending = True
    paths = [base + '/DefaultCacheBehavior']
    behaviors = read(ctx, resource, base + '/CacheBehaviors')
    if isinstance(behaviors, list):
        paths.extend(base + f'/CacheBehaviors/{i}' for i in range(len(behaviors)))
    elif behaviors is not ABSENT:
        paths.append(base + '/CacheBehaviors')
    for path in paths:
        if read(ctx, resource, path) is ABSENT:
            continue
        target = read(ctx, resource, path + '/TargetOriginId')
        verdict = ('PASS' if isinstance(target, str) and target in ids else
                   'NEEDS_REVIEW' if pending or not isinstance(target, str) else 'FAIL')
        results.append(ctx.finding('CLOUDFRONT_CACHE_TARGET_ORIGIN', path + '/TargetOriginId', verdict,
                                  'cache behavior target must name an origin or origin group'))
        grpc = read(ctx, resource, path + '/GrpcConfig/Enabled')
        if grpc is True or grpc is UNKNOWN:
            version = read(ctx, resource, base + '/HttpVersion')
            methods = read(ctx, resource, path + '/AllowedMethods')
            version_fail = isinstance(version, str) and version not in ('http2', 'http2and3')
            methods_fail = isinstance(methods, list) and 'POST' not in methods and all(
                isinstance(method, str) for method in methods)
            verdict = ('NEEDS_REVIEW' if grpc is UNKNOWN else 'FAIL' if version_fail or methods_fail else
                       'PASS' if version in ('http2', 'http2and3') and isinstance(methods, list) and
                       'POST' in methods else 'NEEDS_REVIEW')
            results.append(ctx.finding('CLOUDFRONT_GRPC_HTTP2_POST', path + '/GrpcConfig', verdict,
                                      'gRPC requires HTTP/2 and POST in allowed methods'))
    return results
