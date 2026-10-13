"""Checks for AWS::WorkSpacesWeb::NetworkSettings."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value

SOURCES = {
    'WORKSPACESWEB_VPC_TENANCY': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-workspacesweb-networksettings.html',
    ],
}


@resource_check('AWS::WorkSpacesWeb::NetworkSettings')
def evaluate_workspacesweb_vpc_tenancy(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::WorkSpacesWeb::NetworkSettings':
        p='/properties/VpcId';vpc=linked(ctx,resource,p,'AWS::EC2::VPC');tenancy=value(ctx,vpc,'/properties/InstanceTenancy') if vpc else None
        emit('WORKSPACESWEB_VPC_TENANCY',p,'PASS' if tenancy=='default' else 'FAIL' if tenancy=='dedicated' else 'NEEDS_REVIEW','explicit linked VPC requires default tenancy; omitted defaults, unknown/future values and external VPC state held')
    return results
