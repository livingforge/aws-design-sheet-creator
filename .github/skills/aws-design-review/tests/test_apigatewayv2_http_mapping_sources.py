import pytest
from aws_design_sheet.checks.apigatewayv2.http_mapping_sources import source_verdict
from test_apigatewayv2_targets import check
from test_autoscaling_group_and_scaling_policy import UNKNOWN


@pytest.mark.parametrize('source,expected', [
    ('constant', 'PASS'), ('', 'PASS'), ('$request.header.x-name', 'PASS'),
    ('$request.querystring.name', 'PASS'), ('$request.path', 'PASS'),
    ('$request.path.petId', 'PASS'), ('$request.body', 'PASS'),
    ('$request.body.pet.name', 'PASS'), ('${request.body.pet.name}', 'PASS'),
    ('${request.path.name} ${request.path.id}', 'PASS'),
    ('$context.requestId', 'PASS'), ('$stageVariables.environmentId', 'PASS'),
    ('$request.body..name', 'FAIL'), ('$request.body.items[?(@.x)]', 'FAIL'),
    ('${request.body..name}', 'FAIL'), ('$request.body.items[0]', 'PASS'),
    ('$request.body[0].price', 'PASS'), ('${request.body.items[12].name}', 'PASS'),
    ('$request.body.items[0]..price', 'FAIL'), ('$request.body.items[0][?(@.price)]', 'FAIL'),
    ('$request.body.items[-1]', 'NEEDS_REVIEW'), ('$request.body.items[0:2]', 'NEEDS_REVIEW'),
    ('$request.body.items[*]', 'NEEDS_REVIEW'), ('$request.body.items[00]', 'NEEDS_REVIEW'),
    ("$request.body['..']", 'NEEDS_REVIEW'), ("$request.body['?(']", 'NEEDS_REVIEW'),
    ('$context.futureVariable', 'NEEDS_REVIEW'), ('$response.body.name', 'NEEDS_REVIEW'),
    ('${request.path.name} $request.path.id', 'NEEDS_REVIEW'),
    ('${request.path.name', 'NEEDS_REVIEW'), ('{{resolve:ssm:path}}', 'NEEDS_REVIEW'),
    (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_request_sources(source, expected):
    assert source_verdict(source) == expected
    assert check({'RequestParameters': {'append:header.x': source}})['APIGATEWAYV2_HTTP_MAPPING_SOURCES'] == expected


@pytest.mark.parametrize('source,expected', [('$response.body', 'PASS'), ('$response.body.name', 'PASS'),
    ('$response.header.x-name', 'PASS'), ('${response.body.name}', 'PASS'),
    ('$response.body..name', 'FAIL'), ('$response.body.items[?(@.x)]', 'FAIL'),
    ('$request.path.name', 'NEEDS_REVIEW'), ('$response.body[0]', 'PASS')])
def test_response_sources(source, expected):
    properties = {'ResponseParameters': {'500': {'ResponseParameters': [
        {'Destination': 'append:header.x', 'Source': source}]}}}
    assert check(properties)['APIGATEWAYV2_HTTP_MAPPING_SOURCES'] == expected


def test_unknown_scope_subtype_and_websocket():
    properties = {'RequestParameters': {'append:header.x': '$request.body..bad'}}
    assert check(properties, conditional=True)['APIGATEWAYV2_HTTP_MAPPING_SOURCES'] == 'NEEDS_REVIEW'
    assert 'APIGATEWAYV2_HTTP_MAPPING_SOURCES' not in check(properties, protocol='WEBSOCKET')
    properties['IntegrationSubtype'] = 'SQS-SendMessage'
    assert 'APIGATEWAYV2_HTTP_MAPPING_SOURCES' not in check(properties)
    properties['IntegrationSubtype'] = UNKNOWN
    assert check(properties)['APIGATEWAYV2_HTTP_MAPPING_SOURCES'] == 'NEEDS_REVIEW'
