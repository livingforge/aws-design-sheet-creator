"""CloudFront alias restrictions only when the target type is established."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from .records import route53_records

URL = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53-recordset-aliastarget.html'
SOURCES = {'ROUTE53_CLOUDFRONT_ALIAS_HEALTH': [URL], 'ROUTE53_CLOUDFRONT_PRIVATE_ZONE': [URL]}


@resource_check('AWS::Route53::RecordSet', 'AWS::Route53::RecordSetGroup')
def route53_alias(design, resource):
    ctx = _Context(design, resource)
    if resource.type == 'AWS::Route53::RecordSet':
        records = ['/properties']
    else:
        items = value(ctx, resource, '/properties/RecordSets')
        if items is ABSENT:
            return []
        if not isinstance(items, list):
            return [ctx.finding(rule, '/properties/RecordSets', 'NEEDS_REVIEW', 'record sets are unresolved') for rule in SOURCES]
        records = [f'/properties/RecordSets/{i}' for i in range(len(items))]
    results = route53_records(design, resource)
    for base in records:
        path = base + '/AliasTarget'
        if value(ctx, resource, path) is ABSENT:
            continue
        distribution = linked(ctx, resource, path + '/DNSName', 'AWS::CloudFront::Distribution')
        health = value(ctx, resource, path + '/EvaluateTargetHealth')
        verdict = ('PASS' if health is False or health is ABSENT else
                   'FAIL' if health is True and distribution else 'NEEDS_REVIEW')
        results.append(ctx.finding('ROUTE53_CLOUDFRONT_ALIAS_HEALTH', path + '/EvaluateTargetHealth', verdict,
            'EvaluateTargetHealth cannot be true for an explicitly linked CloudFront distribution; DNS suffix alone does not establish target type'))
        zone = linked(ctx, resource, '/properties/HostedZoneId', 'AWS::Route53::HostedZone')
        if not zone:
            zone = linked(ctx, resource, '/properties/HostedZoneName', 'AWS::Route53::HostedZone')
        verdict = 'NEEDS_REVIEW'
        if zone:
            vpcs = value(ctx, zone, '/properties/VPCs')
            if vpcs is ABSENT:
                verdict = 'PASS'
            elif isinstance(vpcs, list) and vpcs:
                verdict = 'FAIL' if distribution else 'NEEDS_REVIEW'
        results.append(ctx.finding('ROUTE53_CLOUDFRONT_PRIVATE_ZONE', path, verdict,
            'a private zone with explicit VPC associations cannot route to a linked CloudFront distribution; unresolved zone or target type requires review'))
    return results
