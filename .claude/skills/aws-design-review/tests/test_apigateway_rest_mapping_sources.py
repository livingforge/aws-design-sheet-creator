import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(source, parameters=None):
    props = {'Integration': {'Type': 'HTTP', 'RequestParameters': {'integration.request.header.x': source}}}
    if parameters is not None:
        props['RequestParameters'] = parameters
    main = target('method', 'AWS::ApiGateway::Method', **props)
    return next(r['verdict'] for r in run_resource_checks(linked_design(main), main) if r['rule_id'] == 'APIGATEWAY_REST_MAPPING_SOURCES')


@pytest.mark.parametrize('location', ['querystring', 'path', 'header', 'multivaluequerystring', 'multivalueheader'])
@pytest.mark.parametrize('required', [True, False])
def test_declared_parameter(location, required):
    source = 'method.request.' + location + '.name'
    declaration = source.replace('multivalue', '')
    assert check(source, {declaration: required}) == 'PASS'


@pytest.mark.parametrize('source,expected', [
    ("'literal'", 'PASS'), ("''", 'PASS'), ('method.request.body', 'PASS'),
    ('method.request.body.pet.price', 'PASS'), ('method.request.body[0].price', 'PASS'),
    ('method.request.body.pets[12].price', 'PASS'), ('method.request.body[0][1].price', 'PASS'),
    ('method.request.body[-1].price', 'NEEDS_REVIEW'), ('method.request.body[*].price', 'NEEDS_REVIEW'),
    ('method.request.body[0:2]', 'NEEDS_REVIEW'), ("method.request.body['price']", 'NEEDS_REVIEW'),
    ('stageVariables.stageName', 'NEEDS_REVIEW'), ('context.requestId', 'NEEDS_REVIEW'),
    ('plain-literal', 'NEEDS_REVIEW'), ("'unclosed", 'NEEDS_REVIEW'),
    ('${Source}', 'NEEDS_REVIEW'), (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_other_sources(source, expected):
    assert check(source) == expected


@pytest.mark.parametrize('parameters', [None, {}, UNKNOWN, {'method.request.header.name': UNKNOWN}])
def test_missing_or_unknown_declaration(parameters):
    assert check('method.request.header.name', parameters) == 'NEEDS_REVIEW'
