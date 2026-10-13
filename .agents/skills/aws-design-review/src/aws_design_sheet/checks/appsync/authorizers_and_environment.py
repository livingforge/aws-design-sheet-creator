"""Checks for AWS::AppSync::Api, AWS::AppSync::GraphQLApi."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.map_paths import map_paths

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPSYNC_EVENT_LAMBDA_COUNT': [CF+'aws-properties-appsync-api-lambdaauthorizerconfig.html'],
    'APPSYNC_GRAPHQL_LAMBDA_COUNT': [CF+'aws-properties-appsync-graphqlapi-lambdaauthorizerconfig.html'],
    'APPSYNC_ENVIRONMENT_KEYS': [CF+'aws-resource-appsync-graphqlapi.html'],
}


@resource_check('AWS::AppSync::Api', 'AWS::AppSync::GraphQLApi')
def evaluate_appsync_authorizers_and_environment(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type in ('AWS::AppSync::Api','AWS::AppSync::GraphQLApi'):
        event=resource.type=='AWS::AppSync::Api'
        root='/properties/EventConfig/AuthProviders' if event else '/properties/AdditionalAuthenticationProviders'
        providers=value(ctx,resource,root);types=[] if event else [value(ctx,resource,'/properties/AuthenticationType')]
        if isinstance(providers,list):types.extend(value(ctx,resource,root+'/'+str(i)+('/AuthType' if event else '/AuthenticationType')) for i in range(len(providers)))
        elif providers is not ABSENT:types.append(UNKNOWN)
        if providers is not ABSENT or not event:
            count=sum(t=='AWS_LAMBDA' for t in types)
            pending=any(t not in ('API_KEY','AWS_IAM','AMAZON_COGNITO_USER_POOLS','OPENID_CONNECT','AWS_LAMBDA') for t in types)
            emit('APPSYNC_EVENT_LAMBDA_COUNT' if event else 'APPSYNC_GRAPHQL_LAMBDA_COUNT',root,
                 'FAIL' if count>1 else 'NEEDS_REVIEW' if pending else 'PASS','at most one declared AWS_LAMBDA authorizer mode; unknown provider modes and effective invocation permissions remain unverified')
        if not event:
            path='/properties/EnvironmentVariables';raw=value(ctx,resource,path)
            if raw is not ABSENT:
                verdict='NEEDS_REVIEW'
                if map_paths(ctx,resource,path) is not None:
                    keys=list(raw)
                    verdict=('NEEDS_REVIEW' if any(not k.isascii() for k in keys) else 'PASS'
                             if all(re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{1,63}',k) for k in keys) else 'FAIL')
                emit('APPSYNC_ENVIRONMENT_KEYS',path,verdict,'checks documented 2..64 character ASCII keys starting with a letter; Unicode regex interpretation and variable values remain separate')
    return results
