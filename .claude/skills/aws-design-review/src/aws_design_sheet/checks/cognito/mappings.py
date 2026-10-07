"""Explicit Cognito pool schema, provider mappings and client permissions."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
ATTR='https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html'
MAP='https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html'
SOURCES={
 'COGNITO_POOL_MAPPING_MUTABILITY':[CF+'aws-properties-cognito-userpool-schemaattribute.html',CF+'aws-resource-cognito-userpoolidentityprovider.html',ATTR,MAP],
 'COGNITO_CLIENT_MAPPED_WRITE_ATTRIBUTES':[CF+'aws-resource-cognito-userpoolclient.html',MAP,ATTR],
 'COGNITO_USER_LOCAL_DUPLICATE':[CF+'aws-resource-cognito-userpooluser.html',ATTR],
 'COGNITO_USER_CUSTOM_ATTRIBUTE_PREFIX':[CF+'aws-resource-cognito-userpooluser.html',CF+'aws-properties-cognito-userpool-schemaattribute.html',ATTR],
}
STANDARD=set('name family_name given_name middle_name nickname preferred_username profile picture website gender birthdate zoneinfo locale updated_at address email phone_number sub email_verified phone_number_verified'.split())
OIDC_PROFILE=set('name family_name given_name middle_name nickname preferred_username profile picture website gender birthdate zoneinfo locale'.split())


def pool(ctx,r):
    p=linked(ctx,r,'/properties/UserPoolId','AWS::Cognito::UserPool')
    return p if resolved(r) and resolved(p) else None


def schema_names(ctx,p):
    raw=value(ctx,p,'/properties/Schema');rows={};pending=False
    if not isinstance(raw,list) or len(raw)>1000:return {},True
    for i in range(len(raw)):
        base='/properties/Schema/'+str(i);name=value(ctx,p,base+'/Name');dev=value(ctx,p,base+'/DeveloperOnlyAttribute')
        if not literal(name) or ':' in name or '/' in name or '~' in name or dev is not ABSENT and type(dev) is not bool:pending=True;continue
        full=name if name in STANDARD else ('dev:' if dev is True else 'custom:')+name
        rows.setdefault(full,[]).append(base)
    return rows,pending


def mapping_names(ctx,p):
    raw=value(ctx,p,'/properties/AttributeMapping')
    if not isinstance(raw,dict) or '$state' in raw or any(not literal(k) or '/' in k or '~' in k for k in raw):return None
    return set(raw)


def mutable_mappings(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    schema,pending=schema_names(ctx,r);observed=False
    for p in ctx.design.resources:
        if p.type!='AWS::Cognito::UserPoolIdentityProvider' or p.scope!=r.scope:continue
        owner=pool(ctx,p)
        if owner is None:pending=True;continue
        if owner.id!=r.id:continue
        names=mapping_names(ctx,p)
        if names is None:pending=True;continue
        for name in names:
            observed=True;matches=schema.get(name,[])
            if len(matches)!=1:pending=True;continue
            mutable=value(ctx,r,matches[0]+'/Mutable')
            if mutable is False:return 'FAIL'
            if mutable is not True:pending=True
    return 'PASS' if observed and not pending else 'NEEDS_REVIEW'


def client_writes(ctx,r):
    owner=pool(ctx,r);providers=value(ctx,r,'/properties/SupportedIdentityProviders');writes=value(ctx,r,'/properties/WriteAttributes')
    if owner is None or not isinstance(providers,list) or len(providers)>1000:return 'NEEDS_REVIEW'
    if providers and all(p=='COGNITO' for p in providers):return 'NOT_APPLICABLE'
    if not isinstance(writes,list) or any(not literal(w) for w in writes):return 'NEEDS_REVIEW'
    if any(w.startswith('oidc:') and w!='oidc:profile' for w in writes):return 'NEEDS_REVIEW'
    writes=set(writes)
    if 'oidc:profile' in writes:writes=(writes-{'oidc:profile'})|OIDC_PROFILE
    pending=False;observed=False
    for i in range(len(providers)):
        path='/properties/SupportedIdentityProviders/'+str(i);name=value(ctx,r,path)
        if name=='COGNITO':continue
        p=linked(ctx,r,path,'AWS::Cognito::UserPoolIdentityProvider')
        if p is None and literal(name):
            matches=[]
            for candidate in ctx.design.resources:
                if candidate.type!='AWS::Cognito::UserPoolIdentityProvider' or candidate.scope!=r.scope:continue
                other=pool(ctx,candidate)
                if other and other.id==owner.id and value(ctx,candidate,'/properties/ProviderName')==name:matches.append(candidate)
            p=matches[0] if len(matches)==1 else None
        other=pool(ctx,p) if p is not None else None
        if other is None or other.id!=owner.id:pending=True;continue
        names=mapping_names(ctx,p)
        if names is None:pending=True;continue
        observed=True
        if not names.issubset(set(writes)):return 'FAIL'
    return 'PASS' if observed and not pending else 'NEEDS_REVIEW'


def user_duplicate(ctx,r):
    owner=pool(ctx,r);name=value(ctx,r,'/properties/Username')
    if owner is None or not literal(name):return 'NEEDS_REVIEW'
    insensitive=value(ctx,owner,'/properties/UsernameConfiguration/CaseSensitive') is False
    for other in ctx.design.resources:
        if other.id==r.id or other.type!=r.type or other.scope!=r.scope:continue
        otherpool=pool(ctx,other)
        if otherpool is None or otherpool.id!=owner.id:continue
        othername=value(ctx,other,'/properties/Username')
        if literal(othername) and (name==othername or insensitive and name.isascii() and othername.isascii() and name.lower()==othername.lower()):return 'FAIL'
    return 'NEEDS_REVIEW'


@resource_check('AWS::Cognito::UserPool', 'AWS::Cognito::UserPoolClient', 'AWS::Cognito::UserPoolUser')
def evaluate_cognito_mappings(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::Cognito::UserPool':
        emit('COGNITO_POOL_MAPPING_MUTABILITY','/properties/Schema',mutable_mappings(ctx,resource),'mapped attributes in explicit same-pool IdPs require Mutable=true in uniquely named schema rows; defaults, unlisted/ambiguous schemas, external providers and unknown mappings held')
    if resource.type=='AWS::Cognito::UserPoolClient':
        emit('COGNITO_CLIENT_MAPPED_WRITE_ATTRIBUTES','/properties/WriteAttributes',client_writes(ctx,resource),'explicit allowed same-pool IdP mappings must be writable; explicit oidc:profile expands to its 13 documented attributes; omitted defaults, ambiguous providers and external mappings held')
    if resource.type=='AWS::Cognito::UserPoolUser':
        emit('COGNITO_USER_LOCAL_DUPLICATE','/properties/Username',user_duplicate(ctx,resource),'proves duplicate explicit usernames in the same linked pool; ASCII folding only for explicit case-insensitive pool; absence of local duplicates cannot establish live uniqueness')
        owner=pool(ctx,resource);schema,pending=schema_names(ctx,owner) if owner else ({},True)
        for path in expand(ctx,resource,'/properties/UserAttributes/*/Name'):
            name=value(ctx,resource,path);verdict='NEEDS_REVIEW'
            if literal(name):
                if name in STANDARD or name.startswith(('custom:','dev:')):verdict='PASS'
                elif not pending and len(schema.get('custom:'+name,[]))==1:verdict='FAIL'
            emit('COGNITO_USER_CUSTOM_ATTRIBUTE_PREFIX',path,verdict,'known custom schema attribute names need custom: prefix; checks naming only, not attribute existence/value or required signup fields; AdminCreateUser can omit required attributes')
    return results
