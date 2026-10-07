"""Documented HTTP API mapping sources; no JSONPath or variable execution."""
import re
from ...literal_json_path import literal_path_suffix, prohibited_http_selector
from ..common.context_values import value
from ..common.field_reads import ABSENT

SOURCES = {'APIGATEWAYV2_HTTP_MAPPING_SOURCES': [
    'https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-parameter-mapping.html']}


def variable_verdict(variable, response):
    direction = 'response' if response else 'request'
    body = direction + '.body'
    if variable.startswith(body + '.') or variable.startswith(body + '['):
        suffix = variable[len(body):]
        if prohibited_http_selector(suffix):
            return 'FAIL'
        return 'PASS' if literal_path_suffix(suffix) else 'NEEDS_REVIEW'
    if variable == body or not response and variable == 'request.path':
        return 'PASS'
    locations = 'header' if response else 'header|querystring|path'
    if re.fullmatch(direction + r'\.(?:' + locations + r')\.[A-Za-z0-9_-]+', variable):
        return 'PASS'
    if variable == 'context.requestId':
        return 'PASS'
    if re.fullmatch(r'stageVariables\.[A-Za-z0-9_]+', variable):
        return 'PASS'
    return 'NEEDS_REVIEW'


def source_verdict(raw, response=False):
    if not isinstance(raw, str) or '{{' in raw:
        return 'NEEDS_REVIEW'
    if '$' not in raw:
        return 'PASS'
    if raw.startswith('$') and not raw.startswith('${'):
        return variable_verdict(raw[1:], response)
    variables = list(re.finditer(r'\$\{([^{}]+)\}', raw))
    if not variables:
        return 'NEEDS_REVIEW'
    remainder = re.sub(r'\$\{[^{}]+\}', '', raw)
    if '$' in remainder or '{' in remainder or '}' in remainder:
        return 'NEEDS_REVIEW'
    verdicts = [variable_verdict(match[1], response) for match in variables]
    return 'FAIL' if 'FAIL' in verdicts else 'NEEDS_REVIEW' if 'NEEDS_REVIEW' in verdicts else 'PASS'


def mapping_sources(ctx, resource, protocol):
    results = []
    for response, field in ((False, 'RequestParameters'), (True, 'ResponseParameters')):
        path = '/properties/' + field
        parameters = value(ctx, resource, path)
        if parameters is ABSENT or protocol == 'WEBSOCKET':
            continue
        subtype = value(ctx, resource, '/properties/IntegrationSubtype')
        if not response and isinstance(subtype, str) and '{' not in subtype:
            continue
        entries = []
        if protocol != 'HTTP' or not isinstance(parameters, dict) or not response and subtype is not ABSENT:
            entries.append((path, None))
        elif response:
            for status in parameters:
                escaped = status.replace('~', '~0').replace('/', '~1')
                base = path + '/' + escaped + '/ResponseParameters'
                items = value(ctx, resource, base)
                if not isinstance(items, list):
                    entries.append((base, None))
                else:
                    entries.extend((base + f'/{i}/Source', value(ctx, resource, base + f'/{i}/Source')) for i in range(len(items)))
        else:
            for key in parameters:
                item_path = path + '/' + key.replace('~', '~0').replace('/', '~1')
                entries.append((item_path, value(ctx, resource, item_path)))
        for source_path, raw in entries:
            results.append(ctx.finding('APIGATEWAYV2_HTTP_MAPPING_SOURCES', source_path, source_verdict(raw, response),
                'checks supported literal selection syntax and rejects documented recursive-descent/filter body paths; context vocabulary, payload contents, route/stage variable existence and other JSONPath remain unverified'))
    return results
