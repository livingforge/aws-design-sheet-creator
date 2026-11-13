"""VPC membership of an HTTP API VPC link's subnets and security groups.

API Gateway refuses an AWS::ApiGatewayV2::VpcLink whose security groups lie in another VPC
than its subnets ("All subnets and security groups should be in the same VPC"); cfn-lint
1.57.2 does not report it. The REST API VpcLink (AWS::ApiGateway::VpcLink) names load
balancers instead and is checked separately.
"""
from ..registry import resource_check
from ..common.context_values import _Context
from ..common.vpc_membership import vpc_membership

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APIGATEWAYV2_VPC_LINK_VPC_MEMBERSHIP': [
        CF + 'aws-resource-apigatewayv2-vpclink.html',
        'https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-vpc-links.html'],
}


@resource_check('AWS::ApiGatewayV2::VpcLink')
def evaluate_http_api_vpc_link_membership(design, resource):
    return vpc_membership(_Context(design, resource), resource, '/properties',
                          'APIGATEWAYV2_VPC_LINK_VPC_MEMBERSHIP',
                          subnet_key='SubnetIds', security_group_key='SecurityGroupIds',
                          finding_path='/properties/SubnetIds')
