"""Form of an HTTP API model schema.

CloudFormation refuses an AWS::ApiGatewayV2::Model whose Schema is a JSON string instead of an
object (early property validation); cfn-lint 1.57.2 accepts the string. AWS refused it in
aws-emulator-evaluation-suite.
"""
from ..registry import resource_check
from ..common.context_values import _Context, value

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APIGATEWAYV2_MODEL_SCHEMA_OBJECT': [CF + 'aws-resource-apigatewayv2-model.html'],
}


@resource_check('AWS::ApiGatewayV2::Model')
def evaluate_model_schema_object(design, resource):
    ctx = _Context(design, resource)
    schema = value(ctx, resource, '/properties/Schema')
    if isinstance(schema, dict):
        verdict = 'PASS'
    elif isinstance(schema, str):
        verdict = 'FAIL'
    else:
        return []
    return [ctx.finding('APIGATEWAYV2_MODEL_SCHEMA_OBJECT', '/properties/Schema', verdict,
                        'Schema is a JSON object, not a string holding JSON')]
