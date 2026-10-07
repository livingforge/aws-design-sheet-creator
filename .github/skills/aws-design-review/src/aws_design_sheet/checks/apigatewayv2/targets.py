"""API Gateway V2 integration targets proven by literal URIs or explicit links."""
import re
from ..registry import resource_check
from .http_mapping_sources import mapping_sources
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN

URL = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html'
SOURCES = {rule:[URL] for rule in ('APIGATEWAYV2_WEBSOCKET_LAMBDA_POST','APIGATEWAYV2_PRIVATE_TARGET_SCOPE')}
SOURCES['APIGATEWAYV2_MANAGED_PAYLOAD_TARGET'] = [
    'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigatewayv2-apigatewaymanagedoverrides-integrationoverrides.html',
    'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-api.html']
LAMBDA_ARN = r'arn:[a-z0-9-]+:lambda:[a-z0-9-]+:\d{12}:function:[^/\s{}]+'
MAPPING_URL = 'https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-parameter-mapping.html'
SOURCES.update({rule: [URL, MAPPING_URL] for rule in (
    'APIGATEWAYV2_HTTP_REQUEST_DESTINATIONS', 'APIGATEWAYV2_HTTP_RESPONSE_DESTINATIONS')})
RESERVED_HEADERS = frozenset('authorization connection content-encoding content-length content-location forwarded keep-alive origin proxy-authenticate proxy-authorization te trailers transfer-encoding upgrade x-forwarded-for x-forwarded-host x-forwarded-proto via'.split())


def mapping_destination(destination, response=False):
    if not isinstance(destination, str) or '{' in destination:
        return 'NEEDS_REVIEW'
    if response and destination == 'overwrite.statuscode':
        return 'NEEDS_REVIEW'  # CF prose conflicts with the API guide's colon syntax.
    if destination == ('overwrite:statuscode' if response else 'overwrite:path'):
        return 'PASS'
    match = re.fullmatch(r'(append|overwrite|remove):(header|querystring)\.(.+)', destination)
    if not match or (response and match[2] != 'header'):
        return 'FAIL'
    name = match[3].lower()
    if match[2] == 'header' and (name in RESERVED_HEADERS or name.startswith(('access-control-', 'apigw-', 'x-amz-', 'x-amzn-'))):
        return 'FAIL'
    return 'PASS'


def http_mapping_destinations(ctx, resource, protocol):
    results = []
    for response, field, rule in (
        (False, 'RequestParameters', 'APIGATEWAYV2_HTTP_REQUEST_DESTINATIONS'),
        (True, 'ResponseParameters', 'APIGATEWAYV2_HTTP_RESPONSE_DESTINATIONS'),
    ):
        path = '/properties/' + field
        parameters = value(ctx, resource, path)
        if parameters is ABSENT or protocol == 'WEBSOCKET':
            continue
        subtype = value(ctx, resource, '/properties/IntegrationSubtype')
        if not response and isinstance(subtype, str) and '{' not in subtype:
            continue  # AWS service integrations use service-specific request keys.
        verdicts = []
        if protocol != 'HTTP' or not isinstance(parameters, dict) or (not response and subtype is not ABSENT):
            verdicts.append('NEEDS_REVIEW')
        elif not response:
            verdicts.extend(mapping_destination(key) for key in parameters)
        else:
            for status in parameters:
                if not re.fullmatch(r'[2-5]\d\d', status):
                    verdicts.append('NEEDS_REVIEW')
                    continue
                base = path + '/' + status + '/ResponseParameters'
                entries = value(ctx, resource, base)
                if not isinstance(entries, list):
                    verdicts.append('NEEDS_REVIEW')
                    continue
                verdicts.extend(mapping_destination(value(ctx, resource, base + '/' + str(i) + '/Destination'), True) for i in range(len(entries)))
        verdict = 'FAIL' if 'FAIL' in verdicts else 'NEEDS_REVIEW' if 'NEEDS_REVIEW' in verdicts else 'PASS'
        results.append(ctx.finding(rule, path, verdict,
            'HTTP mapping destinations must use documented actions and locations and must not modify reserved headers; source expressions and full name syntax are separate'))
    return results


def lambda_target(ctx, resource, path='/properties/IntegrationUri'):
    for kind in ('AWS::Lambda::Function','AWS::Lambda::Alias','AWS::Lambda::Version'):
        if linked(ctx, resource, path, kind):
            return True
    uri = value(ctx, resource, path)
    if not isinstance(uri,str) or '{' in uri:
        return None
    if re.fullmatch(LAMBDA_ARN,uri) or re.fullmatch(r'arn:[a-z0-9-]+:apigateway:[a-z0-9-]+:lambda:path/2015-03-31/functions/'+LAMBDA_ARN+r'/invocations',uri):
        return True
    if uri.startswith(('http://','https://')):
        return False
    arn = re.fullmatch(r'arn:[a-z0-9-]+:([a-z0-9-]+):[^:]*:[^:]*:.+',uri)
    if arn and arn[1] not in ('lambda','apigateway'):
        return False
    return None


def payload_v2_target(ctx, resource):
    kind = value(ctx, resource, '/properties/IntegrationType')
    if kind != 'AWS_PROXY':
        return ('FAIL','payload format 2.0 requires AWS_PROXY') if kind in ('AWS','HTTP','HTTP_PROXY','MOCK') else ('NEEDS_REVIEW','integration type is unresolved')
    subtype = value(ctx, resource, '/properties/IntegrationSubtype')
    if subtype is not ABSENT:
        return ('FAIL','payload format 2.0 is not supported for AWS service subtypes') if isinstance(subtype,str) and '{{' not in subtype else ('NEEDS_REVIEW','integration subtype is unresolved')
    target = lambda_target(ctx,resource)
    return ('PASS','payload format 2.0 targets a proven Lambda proxy') if target is True else ('FAIL','payload format 2.0 target is explicitly non-Lambda') if target is False else ('NEEDS_REVIEW','integration target is unresolved')


@resource_check('AWS::ApiGatewayV2::Integration')
def integration_targets(design, resource):
    ctx = _Context(design, resource)
    api = linked(ctx, resource, '/properties/ApiId', 'AWS::ApiGatewayV2::Api')
    protocol = value(ctx, api, '/properties/ProtocolType') if api else UNKNOWN
    kind = value(ctx, resource, '/properties/IntegrationType')
    results = http_mapping_destinations(ctx, resource, protocol) + mapping_sources(ctx, resource, protocol)
    if protocol == 'WEBSOCKET' and kind in ('AWS','AWS_PROXY'):
        target = lambda_target(ctx,resource)
        if target is not False:
            method = value(ctx,resource,'/properties/IntegrationMethod')
            verdict = 'NEEDS_REVIEW'
            if target is True:
                verdict = 'FAIL' if method is ABSENT else 'PASS' if method == 'POST' else 'FAIL' if isinstance(method,str) and '{{' not in method else 'NEEDS_REVIEW'
            results.append(ctx.finding('APIGATEWAYV2_WEBSOCKET_LAMBDA_POST','/properties/IntegrationMethod',verdict,
                'a WebSocket Lambda integration requires POST; dynamic or unlinked API/target facts are not inferred'))
    if value(ctx,resource,'/properties/ConnectionType') == 'VPC_LINK':
        verdict = private_target(ctx,resource) if protocol == 'HTTP' else 'NEEDS_REVIEW'
        results.append(ctx.finding('APIGATEWAYV2_PRIVATE_TARGET_SCOPE','/properties/IntegrationUri',verdict,
            'HTTP private integration URI must identify an ALB/NLB listener or Cloud Map service in this account; target state, permissions and other resources remain separate'))
    return results


def private_target(ctx, resource):
    path = '/properties/IntegrationUri'
    service = linked(ctx,resource,path,'AWS::ServiceDiscovery::Service')
    if service:
        return 'PASS' if re.fullmatch(r'\d{12}',resource.scope.account) else 'NEEDS_REVIEW'
    listener = linked(ctx,resource,path,'AWS::ElasticLoadBalancingV2::Listener')
    if listener:
        lb = linked(ctx,listener,'/properties/LoadBalancerArn','AWS::ElasticLoadBalancingV2::LoadBalancer')
        kind = value(ctx,lb,'/properties/Type') if lb else UNKNOWN
        return 'PASS' if kind in (ABSENT,'application','network') and re.fullmatch(r'\d{12}',resource.scope.account) else 'FAIL' if kind == 'gateway' else 'NEEDS_REVIEW'
    uri = value(ctx,resource,path)
    if not isinstance(uri,str) or '{' in uri:
        return 'NEEDS_REVIEW'
    arn = re.fullmatch(r'arn:[a-z0-9-]+:([a-z0-9-]+):[a-z0-9-]+:(\d{12}):([^\s]+)',uri)
    if not arn:
        return 'FAIL' if uri.startswith(('http://','https://')) else 'NEEDS_REVIEW'
    service,account,target = arn.groups()
    allowed = (service=='elasticloadbalancing' and re.fullmatch(r'listener/(app|net)/[^?]+',target)) or (service=='servicediscovery' and re.fullmatch(r'service/[^/?]+(?:\?[^\s]*)?',target))
    if not allowed:
        return 'FAIL' if service in ('elasticloadbalancing','servicediscovery','lambda','sqs','firehose') else 'NEEDS_REVIEW'
    if not re.fullmatch(r'\d{12}',resource.scope.account):
        return 'NEEDS_REVIEW'
    return 'PASS' if account==resource.scope.account else 'FAIL'


@resource_check('AWS::ApiGatewayV2::ApiGatewayManagedOverrides')
def managed_payload_target(design,resource):
    ctx = _Context(design,resource)
    path = '/properties/Integration/PayloadFormatVersion'
    version = value(ctx,resource,path)
    if version is ABSENT:
        return []
    api = linked(ctx,resource,'/properties/ApiId','AWS::ApiGatewayV2::Api')
    protocol = value(ctx,api,'/properties/ProtocolType') if api else UNKNOWN
    verdict = 'NEEDS_REVIEW'
    if protocol == 'HTTP':
        if version == '1.0':
            verdict = 'PASS'
        elif version == '2.0':
            target = lambda_target(ctx,api,'/properties/Target')
            verdict = 'PASS' if target is True else 'FAIL' if target is False else 'NEEDS_REVIEW'
    return [ctx.finding('APIGATEWAYV2_MANAGED_PAYLOAD_TARGET',path,verdict,
        'managed payload 2.0 requires a Lambda quick-create Target on the linked HTTP API; 1.0 supports either target type')]
