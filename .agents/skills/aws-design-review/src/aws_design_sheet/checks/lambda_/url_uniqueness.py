"""One function URL per function and qualifier.

Lambda refuses a second function URL for the same function and qualifier (ResourceConflict),
and cfn-lint 1.57.2 does not compare resources; AWS refused it in aws-emulator-evaluation-suite.
"""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'LAMBDA_URL_ONE_PER_QUALIFIER': [CF + 'aws-resource-lambda-url.html',
                                     'https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html'],
}


def _key(ctx, resource):
    function = linked(ctx, resource, '/properties/TargetFunctionArn', 'AWS::Lambda::Function')
    qualifier = value(ctx, resource, '/properties/Qualifier')
    if function is None or not (qualifier is ABSENT or literal(qualifier)):
        return None
    return function.id, None if qualifier is ABSENT else qualifier


@resource_check('AWS::Lambda::Url')
def evaluate_lambda_url_uniqueness(design, resource):
    ctx = _Context(design, resource)
    key = _key(ctx, resource)
    if key is None:
        return []
    others = sorted(o.name for o in design.resources
                    if o.id != resource.id and o.type == resource.type and _key(_Context(design, o), o) == key)
    verdict = 'FAIL' if others else 'PASS'
    reason = ('the function and qualifier already have the URL ' + ', '.join(others) if others
              else 'no other function URL in the design has this function and qualifier')
    return [ctx.finding('LAMBDA_URL_ONE_PER_QUALIFIER', '/properties/TargetFunctionArn', verdict, reason)]
