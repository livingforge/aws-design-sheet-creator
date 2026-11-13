"""Status code of an API Gateway gateway response.

API Gateway refuses a gateway response status code outside [1-5][0-9][0-9] (BadRequestException);
cfn-lint 1.57.2 does not report it. AWS refused "999" in aws-emulator-evaluation-suite.
"""
import re

from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APIGATEWAY_GATEWAY_RESPONSE_STATUS_CODE': [CF + 'aws-resource-apigateway-gatewayresponse.html',
                                                'https://docs.aws.amazon.com/apigateway/latest/api/API_PutGatewayResponse.html'],
}


@resource_check('AWS::ApiGateway::GatewayResponse')
def evaluate_gateway_response_status_code(design, resource):
    ctx = _Context(design, resource)
    code = value(ctx, resource, '/properties/StatusCode')
    if not literal(code):
        return []
    verdict = 'PASS' if re.fullmatch(r'[1-5][0-9][0-9]', code) else 'FAIL'
    return [ctx.finding('APIGATEWAY_GATEWAY_RESPONSE_STATUS_CODE', '/properties/StatusCode', verdict,
                        'the status code is a three-digit code from 100 to 599')]
