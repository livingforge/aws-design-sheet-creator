"""Checks for AWS::Cognito::IdentityPoolRoleAttachment."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'COGNITO_ROLE_KEYS': [CF+'aws-resource-cognito-identitypoolroleattachment.html'],
    'COGNITO_ROLE_MAPPINGS': [CF+'aws-properties-cognito-identitypoolroleattachment-rolemapping.html',CF+'aws-properties-cognito-identitypoolroleattachment-rulesconfigurationtype.html',CF+'aws-properties-cognito-identitypoolroleattachment-mappingrule.html'],
}


@resource_check('AWS::Cognito::IdentityPoolRoleAttachment')
def evaluate_cognito_identity_pool_role_attachment(design,resource):
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Cognito::IdentityPoolRoleAttachment':
        path='/properties/Roles'; raw=value(ctx,resource,path)
        if raw is not ABSENT:
            pending=not isinstance(raw,dict);invalid=False
            for key in raw if isinstance(raw,dict) else ():
                if not literal(key):pending=True
                elif key not in ('authenticated','unauthenticated'):invalid=True
            emit('COGNITO_ROLE_KEYS',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','literal role keys must be authenticated or unauthenticated; role ARN and trust remain separate')
        path='/properties/RoleMappings'; raw=value(ctx,resource,path)
        if raw is not ABSENT:
            pending=not isinstance(raw,dict);invalid=False
            for key in raw if isinstance(raw,dict) else ():
                if not literal(key) or '/' in key or '~' in key:pending=True;continue
                base=path+'/'+key; kind=value(ctx,resource,base+'/Type')
                if kind not in ('Token','Rules'):pending=True
                else:
                    resolution=value(ctx,resource,base+'/AmbiguousRoleResolution')
                    if resolution is ABSENT:invalid=True
                    elif not literal(resolution):pending=True
                    if kind=='Rules':
                        config=value(ctx,resource,base+'/RulesConfiguration')
                        if config is ABSENT:invalid=True
                        elif not isinstance(config,dict):pending=True
                rules_path=base+'/RulesConfiguration/Rules'; rules=value(ctx,resource,rules_path)
                if kind=='Rules' and rules is ABSENT:invalid=True
                if rules is not ABSENT:
                    if not isinstance(rules,list):pending=True
                    else:
                        known_rules=sum(isinstance(value(ctx,resource,rules_path+'/'+str(i)),dict) for i in range(len(rules)))
                        if known_rules>25:invalid=True
                        if known_rules!=len(rules):pending=True
                        for i in range(len(rules)):
                            match=value(ctx,resource,rules_path+'/'+str(i)+'/MatchType')
                            if not literal(match):pending=True
                            elif match not in ('Equals','Contains','StartsWith','NotEqual'):invalid=True
            emit('COGNITO_ROLE_MAPPINGS',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','checks known Type dependencies, per-entry rule limit and MatchType; escaped provider keys, provider aliases, unresolved values and runtime role selection remain under review')
    return results
