"""Basic SNS endpoint representation checks; never contact an endpoint."""
import re
from urllib.parse import urlsplit
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from .trust import sns_firehose_trust

SOURCES = {'SNS_ENDPOINT_PROTOCOL_FORMAT': ['https://docs.aws.amazon.com/sns/latest/api/API_Subscribe.html']}


@resource_check('AWS::SNS::Subscription', 'AWS::SNS::Topic')
def sns_endpoints(design, resource):
    ctx = _Context(design, resource)
    bases = ['/properties']
    if resource.type == 'AWS::SNS::Topic':
        items = value(ctx, resource, '/properties/Subscription')
        if items is ABSENT:
            return []
        if not isinstance(items, list):
            return [ctx.finding('SNS_ENDPOINT_PROTOCOL_FORMAT', '/properties/Subscription', 'NEEDS_REVIEW', 'subscriptions are unresolved')]
        bases = [f'/properties/Subscription/{i}' for i in range(len(items))]
    results = sns_firehose_trust(design, resource)
    for base in bases:
        endpoint = value(ctx, resource, base + '/Endpoint')
        if endpoint is ABSENT:
            continue  # Neither CF nor Subscribe marks Endpoint unconditionally required.
        protocol = value(ctx, resource, base + '/Protocol')
        verdict = 'NEEDS_REVIEW'
        if isinstance(endpoint, str) and '{{' not in endpoint:
            if protocol in ('http', 'https'):
                try:
                    parts = urlsplit(endpoint)
                    valid = parts.scheme.lower() == protocol and bool(parts.hostname) and not any(c.isspace() for c in endpoint)
                    parts.port  # Invalid/out-of-range literal ports are not URL endpoints.
                    verdict = 'PASS' if valid else 'FAIL'
                except ValueError:
                    verdict = 'FAIL'
            elif isinstance(protocol, str) and protocol in ('sqs', 'lambda', 'firehose', 'application'):
                service, prefix = {'sqs':('sqs',''), 'lambda':('lambda','function:'),
                    'firehose':('firehose','deliverystream/'), 'application':('sns','endpoint/')}[protocol]
                match = re.fullmatch(r'arn:[a-z0-9-]+:([a-z0-9-]+):[a-z0-9-]+:\d{12}:([^{}\s]+)', endpoint)
                valid = bool(match and match[1] == service and match[2].startswith(prefix) and len(match[2]) > len(prefix))
                verdict = 'PASS' if valid else 'FAIL'
        results.append(ctx.finding('SNS_ENDPOINT_PROTOCOL_FORMAT', base + '/Endpoint', verdict,
            'checks HTTP(S) URL syntax or the protocol-specific ARN service/resource prefix only; email/SMS syntax, endpoint existence, reachability and confirmation remain unverified'))
    return results
