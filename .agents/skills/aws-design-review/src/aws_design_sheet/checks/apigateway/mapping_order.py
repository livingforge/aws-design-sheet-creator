"""Private API mapping order within explicit CloudFormation templates."""
import re
from ...template_dependencies import members, ordering
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT

SOURCES={'APIGATEWAY_PRIVATE_MAPPING_STAGE_ORDER':[
    'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-basepathmappingv2.html',
    'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-dependson.html']}


def api_identity(ctx,resource):
    api=linked(ctx,resource,'/properties/RestApiId','AWS::ApiGateway::RestApi')
    if api:return ('resource',api.id)
    raw=value(ctx,resource,'/properties/RestApiId')
    return ('id',raw) if isinstance(raw,str) and re.fullmatch(r'[a-z0-9]+',raw) else None


@resource_check('AWS::ApiGateway::BasePathMappingV2')
def private_mapping_order(design,resource):
    ctx=_Context(design,resource)
    path='/properties/Stage'
    raw=value(ctx,resource,path)
    if raw is ABSENT:return []
    pool=members(design,resource)
    stage=linked(ctx,resource,path,'AWS::ApiGateway::Stage')
    targets=[stage] if stage and stage in pool else []
    api=api_identity(ctx,resource)
    if not stage and isinstance(raw,str) and re.fullmatch(r'[A-Za-z0-9_-]+',raw) and api:
        targets=[other for other in pool if other.type=='AWS::ApiGateway::Stage'
                 and value(ctx,other,'/properties/StageName')==raw and api_identity(ctx,other)==api]
    if len(targets)!=1:
        return [ctx.finding('APIGATEWAY_PRIVATE_MAPPING_STAGE_ORDER','/template/depends_on','NEEDS_REVIEW',
            'one stage in the same explicit template must be identified; external stages, deployment-created stages and ambiguous references remain unverified')]
    return [ordering(ctx,'APIGATEWAY_PRIVATE_MAPPING_STAGE_ORDER',targets)]
