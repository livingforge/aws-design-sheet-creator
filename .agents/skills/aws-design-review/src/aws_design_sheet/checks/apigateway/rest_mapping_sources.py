"""REST integration source forms and declared method-parameter references."""
import re
from ...literal_json_path import literal_path_suffix
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

SOURCES = {'APIGATEWAY_REST_MAPPING_SOURCES': [
    'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-method-integration.html',
    'https://docs.aws.amazon.com/apigateway/latest/developerguide/request-response-data-mappings.html']}


@resource_check('AWS::ApiGateway::Method')
def rest_mapping_sources(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/Integration/RequestParameters'
    mappings = value(ctx, resource, path)
    if mappings is ABSENT:
        return []
    if not isinstance(mappings, dict):
        return [ctx.finding('APIGATEWAY_REST_MAPPING_SOURCES', path, 'NEEDS_REVIEW', 'mapping is unresolved')]
    results = []
    for key in mappings:
        item_path = path + '/' + key.replace('~', '~0').replace('/', '~1')
        source = value(ctx, resource, item_path)
        verdict = 'NEEDS_REVIEW'
        if isinstance(source, str) and '${' not in source and '{{' not in source:
            parameter = re.fullmatch(r'method\.request\.(querystring|path|header|multivaluequerystring|multivalueheader)\.([A-Za-z0-9_-]+)', source)
            if parameter:
                candidates = [source]
                if parameter[1].startswith('multivalue'):
                    candidates.append('method.request.' + parameter[1].removeprefix('multivalue') + '.' + parameter[2])
                declared = [value(ctx, resource, '/properties/RequestParameters/' + candidate) for candidate in candidates]
                if any(type(item) is bool for item in declared):
                    verdict = 'PASS'
            elif source.startswith('method.request.body') and literal_path_suffix(source[len('method.request.body'):]):
                verdict = 'PASS'
            elif re.fullmatch(r"'[^'\\]*'", source):
                verdict = 'PASS'
        results.append(ctx.finding('APIGATEWAY_REST_MAPPING_SOURCES', item_path, verdict,
            'recognizes quoted static/body source syntax or an explicitly declared method parameter, including multivalue aliases; absent declarations, complex paths, variable forms, encoding and runtime payload remain unverified'))
    return results
