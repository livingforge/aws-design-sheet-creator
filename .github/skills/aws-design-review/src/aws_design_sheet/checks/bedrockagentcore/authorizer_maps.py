"""Checks for these resource types:

- AWS::BedrockAgentCore::Gateway
- AWS::BedrockAgentCore::GatewayRateLimit
- AWS::BedrockAgentCore::OAuth2CredentialProvider
"""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

SOURCES = {
    'AGENTCORE_ADVERTISED_SCOPES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-bedrockagentcore-gateway-customjwtauthorizerconfiguration.html',
    ],
    'AGENTCORE_RATE_DIMENSIONS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-bedrockagentcore-gatewayratelimit-limitentry.html',
    ],
    'AGENTCORE_RESERVED_CLAIMS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-bedrockagentcore-oauth2credentialprovider-privatekeyjwtconfig.html',
    ],
}


@resource_check('AWS::BedrockAgentCore::Gateway','AWS::BedrockAgentCore::GatewayRateLimit','AWS::BedrockAgentCore::OAuth2CredentialProvider')
def evaluate_bedrockagentcore_authorizer_maps(design,resource):
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::BedrockAgentCore::Gateway':
        base='/properties/AuthorizerConfiguration/CustomJWTAuthorizer'; path=base+'/AdvertisedScopeMapping'; raw=value(ctx,resource,path)
        if raw is not ABSENT:
            allowed=value(ctx,resource,base+'/AllowedScopes')
            scopes=[value(ctx,resource,base+'/AllowedScopes/'+str(i)) for i in range(len(allowed))] if isinstance(allowed,list) else []
            complete=isinstance(allowed,list) and all(literal(s) for s in scopes)
            known={s for s in scopes if literal(s)}; pending=not isinstance(raw,dict); invalid=False
            for key in raw if isinstance(raw,dict) else ():
                if not literal(key):pending=True
                elif key not in known:
                    if complete:invalid=True
                    else:pending=True
            emit('AGENTCORE_ADVERTISED_SCOPES',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','each literal advertised-scope key must occur in AllowedScopes; unknown membership is held; scope values and identity-provider behavior are separate')
    if resource.type=='AWS::BedrockAgentCore::GatewayRateLimit':
        keys=value(ctx,resource,'/properties/DimensionKeys')
        ordered=[value(ctx,resource,'/properties/DimensionKeys/'+str(i)) for i in range(len(keys))] if isinstance(keys,list) else []
        complete=isinstance(keys,list) and all(literal(k) for k in ordered)
        complete=complete and len(set(ordered))==len(ordered)
        for path in expand(ctx,resource,'/properties/Entries/*/Dimensions'):
            raw=value(ctx,resource,path); pending=not complete or not isinstance(raw,dict); invalid=False
            if isinstance(raw,dict) and complete:
                if all(literal(k) for k in raw):invalid=set(raw)!=set(ordered)
                else:pending=True
                wildcard_seen=False
                for key in ordered:
                    if '/' in key or '~' in key:pending=True;continue
                    item=value(ctx,resource,path+'/'+key)
                    if not literal(item):pending=True
                    elif item=='*':wildcard_seen=True
                    elif '*' in item:pending=True
                    elif wildcard_seen:invalid=True
            emit('AGENTCORE_RATE_DIMENSIONS',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','dimension key sets must match; exact * values may only form a trailing suffix in DimensionKeys order; partial globs, escaped keys, duplicate/unknown parent keys are held')
    if resource.type=='AWS::BedrockAgentCore::OAuth2CredentialProvider':
        base='/properties/Oauth2ProviderConfigInput/CustomOauth2ProviderConfig/PrivateKeyJwtConfig'
        for suffix,forbidden in [('AdditionalHeaderClaims',{'alg','typ'}),('AdditionalPayloadClaims',{'iss','sub','jti','exp'})]:
            path=base+'/'+suffix; raw=value(ctx,resource,path)
            if raw is ABSENT:continue
            pending=not isinstance(raw,dict) or any(not literal(k) for k in raw)
            invalid=isinstance(raw,dict) and bool(set(raw)&forbidden)
            emit('AGENTCORE_RESERVED_CLAIMS',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','checks explicitly documented reserved claim names only; additional service-generated claims and authentication applicability remain separate')
    return results
