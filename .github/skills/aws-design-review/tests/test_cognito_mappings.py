from pathlib import Path
import pytest
from aws_design_sheet.checks.cognito.mappings import evaluate_cognito_mappings
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def found(d,r,rule):return next(f['verdict'] for f in evaluate_cognito_mappings(d,r) if f['rule_id']==rule)


@pytest.mark.parametrize('case',['mutable','immutable','unknown','custom','unprefixed','developer','duplicate','external','conditional','other_pool','missing_schema'])
def test_mutability(case):
    custom=case in ('custom','unprefixed','developer')
    row={'Name':'department' if custom else 'email','Mutable':False if case=='immutable' else UNKNOWN if case=='unknown' else True}
    if case=='developer':row['DeveloperOnlyAttribute']=True
    p=target('pool','AWS::Cognito::UserPool',Schema=[] if case=='missing_schema' else [row,row] if case=='duplicate' else [row])
    other=target('other','AWS::Cognito::UserPool')
    key='dev:department' if case=='developer' else 'department' if case=='unprefixed' else 'custom:department' if custom else 'email'
    provider=target('idp','AWS::Cognito::UserPoolIdentityProvider',UserPoolId='pool',AttributeMapping={key:'claim'})
    d=linked_design(p,[other,provider])
    if case!='external':link(d,provider,'UserPoolId',other if case=='other_pool' else p,'maybe' if case=='conditional' else None)
    assert found(d,p,'COGNITO_POOL_MAPPING_MUTABILITY')==('FAIL' if case=='immutable' else 'PASS' if case in ('mutable','custom','developer') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('case',['writable','not_writable','unknown_writes','unknown_mapping','external','conditional','duplicate','other_pool','linked','builtin','default','oidc_profile'])
def test_client(case):
    p=target('pool','AWS::Cognito::UserPool');other=target('other','AWS::Cognito::UserPool')
    idp=target('idp','AWS::Cognito::UserPoolIdentityProvider',UserPoolId='pool',ProviderName='MyIdP',AttributeMapping=UNKNOWN if case=='unknown_mapping' else {'custom:department':'claim'})
    props={} if case=='default' else {'WriteAttributes':UNKNOWN if case=='unknown_writes' else ['oidc:profile'] if case=='oidc_profile' else [] if case=='not_writable' else ['custom:department']}
    client=target('main','AWS::Cognito::UserPoolClient',UserPoolId='pool',SupportedIdentityProviders=['COGNITO' if case=='builtin' else 'MyIdP'],**props)
    d=linked_design(client,[p,other,idp],[('UserPoolId','pool')])
    if case!='external':link(d,idp,'UserPoolId',other if case=='other_pool' else p,'maybe' if case=='conditional' else None)
    if case=='duplicate':
        copy=idp.model_copy(deep=True);copy.id='copy';d.resources.append(copy);link(d,copy,'UserPoolId',p)
    if case=='linked':link(d,client,'SupportedIdentityProviders/0',idp)
    assert found(d,client,'COGNITO_CLIENT_MAPPED_WRITE_ATTRIBUTES')==('FAIL' if case in ('not_writable','oidc_profile') else 'PASS' if case in ('writable','linked') else 'NOT_APPLICABLE' if case=='builtin' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('case',['same','different','insensitive','sensitive','unknown_case','external','conditional','other_pool','scope'])
def test_username_duplicate(case):
    p=target('pool','AWS::Cognito::UserPool',UsernameConfiguration={'CaseSensitive':False if case=='insensitive' else UNKNOWN if case=='unknown_case' else True});p2=target('pool2','AWS::Cognito::UserPool')
    r=target('main','AWS::Cognito::UserPoolUser',Username='Alice',UserPoolId='pool')
    other=target('other','AWS::Cognito::UserPoolUser',Username='alice' if case in ('insensitive','sensitive','unknown_case') else 'Bob' if case=='different' else 'Alice',UserPoolId='pool')
    d=linked_design(r,[p,p2,other],[('UserPoolId','pool')])
    if case!='external':link(d,other,'UserPoolId',p2 if case=='other_pool' else p,'maybe' if case=='conditional' else None)
    if case=='scope':other.scope.account='222222222222'
    assert found(d,r,'COGNITO_USER_LOCAL_DUPLICATE')==('FAIL' if case in ('same','insensitive') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('name,expected',[('department','FAIL'),('custom:department','PASS'),('email','PASS'),('unknown','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_attribute_prefix(name,expected):
    p=target('pool','AWS::Cognito::UserPool',Schema=[{'Name':'department','Mutable':True}])
    r=target('main','AWS::Cognito::UserPoolUser',UserPoolId='pool',UserAttributes=[{'Name':name,'Value':'test'}])
    assert found(linked_design(r,[p],[('UserPoolId','pool')]),r,'COGNITO_USER_CUSTOM_ATTRIBUTE_PREFIX')==expected


def test_checker_and_required_attribute_admin_exception():
    p=target('pool','AWS::Cognito::UserPool',Schema=[{'Name':'email','Mutable':False,'Required':True}])
    idp=target('idp','AWS::Cognito::UserPoolIdentityProvider',AttributeMapping={'email':'email'},UserPoolId='pool')
    user=target('user','AWS::Cognito::UserPoolUser',UserPoolId='pool',MessageAction='SUPPRESS')
    d=linked_design(p,[idp,user]);link(d,idp,'UserPoolId',p);link(d,user,'UserPoolId',p)
    root=Path(__file__).resolve().parents[1]
    rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='COGNITO_POOL_MAPPING_MUTABILITY' and f['verdict']=='FAIL' for f in rows)
    assert not any(f['verdict']=='FAIL' for f in evaluate_cognito_mappings(d,user))
