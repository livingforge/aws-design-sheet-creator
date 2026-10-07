"""Checks for AWS::AppSync::ChannelNamespace, AWS::AppSync::FunctionConfiguration."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPSYNC_FUNCTION_DATASOURCE_API': [CF+'aws-resource-appsync-functionconfiguration.html', 'https://docs.aws.amazon.com/appsync/latest/APIReference/API_CreateFunction.html', CF+'aws-resource-appsync-datasource.html'],
    'APPSYNC_CHANNEL_NAME_UNIQUE': [CF+'aws-resource-appsync-channelnamespace.html'],
    'APPSYNC_HANDLER_DATASOURCE_API': [CF+'aws-properties-appsync-channelnamespace-integration.html'],
}


def api_identity(ctx,resource,expected='AWS::AppSync::GraphQLApi'):
    if not known_scope(resource):return None
    api=linked(ctx,resource,'/properties/ApiId',expected)
    if api:return ('resource',api.id)
    raw=value(ctx,resource,'/properties/ApiId')
    return ('literal',raw) if literal(raw) and re.fullmatch(r'[A-Za-z0-9]+',raw) else None


@resource_check('AWS::AppSync::ChannelNamespace','AWS::AppSync::FunctionConfiguration')
def evaluate_appsync_channel_and_function(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::AppSync::ChannelNamespace':
        name=value(ctx,resource,'/properties/Name');own=api_identity(ctx,resource,'AWS::AppSync::Api')
        pending=not literal(name) or own is None;duplicate=False
        for other in design.resources:
            if other.id==resource.id or other.type!=resource.type or other.scope!=resource.scope:continue
            other_name=value(ctx,other,'/properties/Name')
            if literal(name) and literal(other_name) and other_name!=name:continue
            api=api_identity(ctx,other,'AWS::AppSync::Api')
            if own and api and own[0]==api[0] and own!=api:continue
            if literal(name) and name==other_name and own and api==own:duplicate=True
            else:pending=True
        emit('APPSYNC_CHANNEL_NAME_UNIQUE','/properties/Name','FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS',
             'literal channel names must be unique within the same known API and design scope; unknown aliases and external namespaces remain unverified')
        for handler in ('OnPublish','OnSubscribe'):
            path='/properties/HandlerConfigs/'+handler+'/Integration/DataSourceName'
            if value(ctx,resource,path) is ABSENT:continue
            source=linked(ctx,resource,path,'AWS::AppSync::DataSource')
            other=api_identity(ctx,source,'AWS::AppSync::Api') if source else None
            verdict='NEEDS_REVIEW'
            if own and other and own[0]==other[0]:verdict='PASS' if own==other else 'FAIL'
            emit('APPSYNC_HANDLER_DATASOURCE_API',path,verdict,'explicit handler data source must belong to the same API; only comparable API identities are checked, data source kind/support and external configuration remain separate')
    if resource.type=='AWS::AppSync::FunctionConfiguration':
        path='/properties/DataSourceName';source=linked(ctx,resource,path,'AWS::AppSync::DataSource')
        own=api_identity(ctx,resource);other=api_identity(ctx,source) if source else None
        verdict='NEEDS_REVIEW'
        if own and other and own[0]==other[0]:verdict='PASS' if own==other else 'FAIL'
        emit('APPSYNC_FUNCTION_DATASOURCE_API',path,verdict,'explicit data source relation must have the same API identity; conditional/cross-scope links, mixed literal/resource identities and external sources remain unresolved')
    return results
